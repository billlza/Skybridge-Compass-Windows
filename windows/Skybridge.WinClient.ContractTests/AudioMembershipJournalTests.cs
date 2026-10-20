using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using static AudioAccountMembershipTests;

internal static partial class AudioObservationJournalTests
{
    private static async Task FreshMembership()
    {
        await using var f = await Fixture.Create(checkpoints: false); using var inbox = new Inbox(f.Binding);
        var before = f.Storage.Load();
        f.OnSend = (path, _) => {
            var pending = f.Read().Pending.Single();
            Require(path == "/api/devices/list" && pending.MembershipPeer == f.Target && !pending.Contradicted,
                "The playback GET had no exact durable membership owner.");
            return Task.FromResult(f.Response(path));
        };
        var lease = await f.Provider.LeaseAsync(inbox, default); var after = f.Storage.Load(); var state = f.Read();
        var saved = state.Checkpoints.Single();
        Require(f.HttpCalls == 1 && state.Pending.Length == 0 && saved.EvidenceId == lease.Evidence.Id &&
            saved.Issued == lease.Evidence.Issued && saved.Expires == lease.Evidence.Expires &&
            after.Session == before.Session && after.LoginId == before.LoginId,
            "The runtime grant differs from the original finite checkpoint or changed its account.");
        f.Clock.Advance(50_000);
        var recovered = saved.Restore(state.LoginId, f.Epoch.Scope, Local(f.Binding), Peer(f.Binding), f.Clock.Read, f.Continuity);
        Require(recovered.Id == lease.Evidence.Id && recovered.Issued == saved.Issued && recovered.Expires == saved.Expires,
            "Independent canonical readback renewed or changed the grant.");
        var cached = await f.Provider.LeaseAsync(inbox, default);
        Require(cached.Evidence.Id == saved.EvidenceId && f.HttpCalls == 1 && f.Storage.Load().Version == after.Version,
            "Process-local reuse silently refreshed or rewrote finite authority.");
    }

    private static async Task ContinuedMembership()
    {
        await using var f = await Fixture.Create(checkpoints: false); using var inbox = new Inbox(f.Binding);
        var lease = await f.Provider.LeaseAsync(inbox, default); var original = lease.Evidence;
        f.Clock.Advance(40_000);
        Require(ReferenceEquals(await f.Provider.RenewAsync(inbox, lease, default), lease), "Continuation replaced its consumer.");
        var saved = f.Read().Checkpoints.Single();
        Require(f.HttpCalls == 2 && saved.EvidenceId == lease.Evidence.Id && saved.EvidenceId != original.Id &&
            saved.Issued == f.Clock.Now && saved.Expires == lease.Evidence.Expires,
            "Explicit fresh continuation did not persist its actual new observation.");
        await Throws<AudioMembershipException>(() => {
            original.RequireValid(f.Epoch.Scope, Local(f.Binding), Peer(f.Binding), f.Clock.Read()); return Task.CompletedTask;
        });
    }

    private static async Task CanceledNegativeMembership()
    {
        foreach (bool cancel in new[] { false, true })
        {
            await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding);
            using var canceled = new CancellationTokenSource(); f.Rows[1]["status"] = "frozen";
            f.OnSend = (path, _) => {
                // QueryAsync samples receipt time after the wire parser returned
                // a complete snapshot. Cancel there, not before parsing.
                if (cancel) f.Clock.OnRead = canceled.Cancel;
                return Task.FromResult(f.Response(path));
            };
            if (cancel) await Throws<OperationCanceledException>(() => f.Provider.LeaseAsync(inbox, canceled.Token));
            else Require((await Throws<AudioMembershipException>(() => f.Provider.LeaseAsync(inbox, default))).Reason == AudioMembershipFailure.InactiveDevice,
                "A frozen peer lost its verified denial reason.");
            var state = f.Read();
            Require(state.Pending.Length == 0 && state.Checkpoints.Length == 1 && state.Checkpoints[0].Peer.Matches(f.Other),
                "A parsed peer denial was discarded or changed an unrelated checkpoint.");
        }
    }

    private static async Task SupersededMembership()
    {
        await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.OnSend = (path, _) => {
            if (path != "/api/devices/list") return Task.FromResult(f.Response(path));
            entered.TrySetResult(); return response.Task;
        };
        var waiting = f.Provider.LeaseAsync(inbox, default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try { await f.Remove(); }
        finally { response.TrySetResult(Reply(f.ListBody())); }
        await Throws<AudioMembershipSupersededException>(() => waiting);
        var state = f.Read();
        Require(state.Pending.Length == 0 && state.Checkpoints.Length == 1 && state.Checkpoints[0].Peer.Matches(f.Other),
            "A superseded positive response restored its peer or removed unrelated authority.");
    }

    private static async Task CrossProviderContradiction()
    {
        foreach (bool matching in new[] { true, false })
        {
            await using var f = await Fixture.Create();
            var binding = matching ? f.Binding : AudioAccountMembershipTests.Binding(peer: 1);
            using var inbox = new Inbox(binding);
            await using var other = new AudioAccountMembershipProvider(f.Http, () => f.Owner.ReadAudioAuthorization(),
                (epoch, token) => f.Owner.GetAudioAuthenticationAsync(epoch, token), f.Clock.Read, continuity: f.Continuity);
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var release = new ManualResetEventSlim();
            f.Continuity.BeforeCreate = () => {
                entered.TrySetResult();
                if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Sealing barrier was not released.");
            };
            var waiting = other.LeaseAsync(inbox, default);
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
                await f.Remove(); // Its observer belongs to f.Provider, not 'other'.
                var pending = f.Read().Pending.Single();
                Require(pending.Contradicted == matching && pending.MembershipPeer!.Matches(Peer(binding)),
                    "Durable revocation did not retain its exact pending target.");
            }
            finally { release.Set(); }
            if (matching) await Throws<InvalidOperationException>(() => waiting);
            else (await waiting).RequireCurrent();
            var state = f.Read();
            Require(state.Pending.Length == 0 && state.Checkpoints.All(c => c.Peer != f.Target) &&
                state.Checkpoints.Length == 1, "A late query revived a removed peer or erased the unrelated grant.");
        }
    }

    private static async Task MembershipPreparationFaults()
    {
        foreach (int fault in new[] { 1, 2 })
        {
            await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding); var before = f.Read();
            f.Committer.NextFault = fault;
            var error = await Throws<AudioMembershipJournalException>(() => f.Provider.LeaseAsync(inbox, default));
            var state = f.Read();
            Require(error.Stage == "preparation" && error.InnerException is AudioJournalStorageException && f.HttpCalls == 0 &&
                state.Checkpoints.SequenceEqual(before.Checkpoints) && state.Pending.Length == (fault == 1 ? 0 : 1) &&
                f.Owner.ReadAudioAuthorization() is null, "Failed preparation issued HTTP or concealed uncertain persistence.");
        }
    }

    private static async Task MembershipCompletionFaults()
    {
        foreach (int fault in new[] { 1, 2 })
        {
            await using var f = await Fixture.Create(checkpoints: false); using var inbox = new Inbox(f.Binding);
            f.OnSend = (path, _) => { f.Committer.NextFault = fault; return Task.FromResult(f.Response(path)); };
            var error = await Throws<AudioMembershipJournalException>(() => f.Provider.LeaseAsync(inbox, default));
            var state = f.Read();
            Require(error.Stage == "completion" && error.InnerException is AudioJournalStorageException &&
                state.Pending.Length == (fault == 1 ? 1 : 0) && state.Checkpoints.Length == (fault == 1 ? 0 : 1) &&
                f.Owner.ReadAudioAuthorization() is null && f.HttpCalls == 1,
                "Uncertain commit was retried, published a lease, or misreported the actual replacement.");
        }
    }

    private static async Task MembershipQueryFailures()
    {
        foreach (string kind in new[] { "temporary", "timeout", "denied", "tls", "malformed" })
        {
            await using var f = await Fixture.Create(queryTimeout: TimeSpan.FromMilliseconds(100));
            using var inbox = new Inbox(f.Binding); var before = f.Read();
            f.OnSend = async (_, token) => {
                if (kind == "timeout") { await Task.Delay(Timeout.InfiniteTimeSpan, token); throw new Exception("Missing timeout."); }
                return kind switch {
                    "temporary" => throw new HttpRequestException(HttpRequestError.ConnectionError, "Synthetic unavailable route."),
                    "denied" => Reply("{\"error\":\"device_revoked\"}", HttpStatusCode.Forbidden),
                    "tls" => throw new HttpRequestException(HttpRequestError.SecureConnectionError, "Synthetic TLS failure."),
                    "malformed" => Reply("{\"devices\":[]}"),
                    _ => throw new Exception("Unknown failure case.")
                };
            };
            var error = await Throws<Exception>(() => f.Provider.LeaseAsync(inbox, default));
            bool temporary = kind is "temporary" or "timeout"; var state = f.Read();
            Require(state.Pending.Length == 0 && (temporary ? state.Checkpoints.SequenceEqual(before.Checkpoints) : state.Checkpoints.Length == 0) &&
                error is not AudioMembershipJournalException && error is not AggregateException,
                "Query outcome was hidden, retained terminal authority, or renewed temporary evidence.");
            if (kind == "timeout") Require(error is AudioMembershipQueryTimeoutException, "Query deadline lost its typed cause.");
        }
    }

    private static async Task MembershipCancellation()
    {
        foreach (bool duringPreparation in new[] { true, false })
        {
            await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding);
            using var canceled = new CancellationTokenSource(); var before = f.Read();
            if (duringPreparation) f.Committer.BeforeCommit = () => { f.Committer.BeforeCommit = null; canceled.Cancel(); };
            else f.Continuity.BeforeCreate = canceled.Cancel;
            await Throws<OperationCanceledException>(() => f.Provider.LeaseAsync(inbox, canceled.Token));
            var state = f.Read();
            Require(state.Pending.Length == 0 && state.Checkpoints.SequenceEqual(before.Checkpoints) &&
                f.HttpCalls == (duringPreparation ? 0 : 1), "Cancellation orphaned its owner or issued fresh authority.");
        }
    }

    private static async Task MembershipSealFailure()
    {
        await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding);
        f.Continuity.BeforeCreate = () => throw new CryptographicException("Synthetic seal failure.");
        await Throws<CryptographicException>(() => f.Provider.LeaseAsync(inbox, default));
        Require(f.Read().Pending.Length == 0 && f.Read().Checkpoints.Length == 0,
            "Failed sealing issued or retained offline authority as a temporary outage.");
    }

    private static async Task MembershipReplacement()
    {
        await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.OnSend = (_, _) => { entered.TrySetResult(); return response.Task; };
        var waiting = f.Provider.LeaseAsync(inbox, default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Require((await f.Owner.SignOutAsync()).Success && (await f.Owner.ApplyAuthAsync(f.Token)).Success, "Fixture account replacement failed.");
        var replacement = f.Storage.Load(); response.SetResult(Reply(f.ListBody()));
        await Throws<Exception>(() => waiting);
        Require(f.Storage.Load().Version == replacement.Version && f.Read().Pending.Length == 0 && f.Read().Checkpoints.Length == 0,
            "Late membership result wrote into its replacement login.");
    }

    private static async Task LegacyJournal()
    {
        await using var f = await Fixture.Create();
        var ticket = await f.Journal.BeginAsync(f.Epoch, Local(f.Binding), AccountDeviceRegistryRequest.Presence, null, default);
        var current = f.Read(); var legacy = JsonSerializer.SerializeToNode(current)!.AsObject(); legacy["SchemaVersion"] = 1;
        foreach (var node in legacy["Pending"]!.AsArray())
        { node!.AsObject().Remove("MembershipPeer"); node.AsObject().Remove("Contradicted"); }
        var read = AudioAccountJournalState.Read(JsonSerializer.SerializeToElement(legacy));
        Require(read.SchemaVersion == AudioAccountJournalState.CurrentSchema && read.Pending.Single() == ticket.Request &&
            read.Checkpoints.SequenceEqual(current.Checkpoints), "Legacy migration changed authority or lost an unsettled observation.");
        foreach (string field in new[] { "Id", "Kind", "Caller", "RemovalTarget", "MembershipPeer", "Contradicted" })
        {
            var incomplete = JsonSerializer.SerializeToNode(current)!.AsObject();
            incomplete["Pending"]![0]!.AsObject().Remove(field);
            await Throws<InvalidDataException>(() => { AudioAccountJournalState.Read(JsonSerializer.SerializeToElement(incomplete)); return Task.CompletedTask; });
        }
        legacy["Pending"]![0]!["MembershipPeer"] = JsonSerializer.SerializeToNode(f.Target);
        await Throws<InvalidDataException>(() => { AudioAccountJournalState.Read(JsonSerializer.SerializeToElement(legacy)); return Task.CompletedTask; });
        await f.Journal.CompleteAsync(ticket, new(null, null, false), null);
    }

    private static async Task MembershipBinding()
    {
        await using var f = await Fixture.Create(); var epoch = f.Epoch; var store = f.Journal;
        var observation = AudioRegistryObservation.FromResponse(f.Authentication, Local(f.Binding),
            new(f.Clock.Now.WallMilliseconds, f.Binding.LocalDeviceId, false, [Entry(Local(f.Binding), true), Entry(Peer(f.Binding))]),
            f.Clock.Now, f.Clock.Now);
        var original = f.Read().Checkpoints.Single(c => c.Peer == f.Target);
        var owned = await store.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.List, null, default, Peer(f.Binding));
        foreach (var invalid in new[] { original with { LoginId = Guid.NewGuid() }, original with { Peer = AudioCheckpointIdentity.From(f.Other) },
            original with { Issued = new(original.Issued.WallMilliseconds + 1, original.Issued.ContinuousMilliseconds + 1) } })
        {
            var before = f.Storage.Load();
            await Throws<InvalidDataException>(() => store.CompleteAsync(owned, new(observation, null, false, invalid), null).AsTask());
            Require(f.Storage.Load().Version == before.Version, "Checkpoint substitution mutated the canonical account.");
        }
        await store.CompleteAsync(owned, new(observation, null, false), new OperationCanceledException());
        var listing = await store.BeginAsync(epoch, Local(f.Binding), AccountDeviceRegistryRequest.List, null, default);
        await Throws<InvalidDataException>(() => store.CompleteAsync(listing, new(observation, null, false, original), null).AsTask());
        await store.CompleteAsync(listing, new(observation, null, false), null);
    }

    private static async Task MembershipCapacity()
    {
        foreach (bool expired in new[] { true, false })
        {
            await using var f = await Fixture.Create(); using var inbox = new Inbox(f.Binding);
            var state = f.Read(); var prototype = state.Checkpoints[0];
            var peers = Enumerable.Range(100, AudioAccountJournalState.Capacity)
                .Select(id => Peer(AudioAccountMembershipTests.Binding(peer: id))).ToArray();
            var full = state with { Checkpoints = peers.Select(peer => prototype with {
                EvidenceId = Guid.NewGuid(), Peer = AudioCheckpointIdentity.From(peer)
            }).ToArray() };
            f.Rows.AddRange(peers.Select(peer => Row(peer)));
            var head = f.Storage.Load();
            Require(((ISessionAudioStateStore)f.Storage).WriteAudioState(JsonSerializer.SerializeToElement(full),
                head.Version!, state.LoginId).Succeeded, "Full canonical checkpoint fixture did not commit.");
            f.Owner = new(f.Client, f.Storage);
            Require((await f.Owner.HydrateFromStoreAsync()).Success, "Full fixture online hydration failed.");
            if (expired)
            {
                f.Clock.Advance(AudioAccountMembershipEvidence.MaximumLifetimeMilliseconds + 1);
                var lease = await f.Provider.LeaseAsync(inbox, default);
                var saved = f.Read();
                Require(saved.Pending.Length == 0 && saved.Checkpoints.Single().EvidenceId == lease.Evidence.Id,
                    "Expired checkpoints prevented a newly verified device from connecting.");
            }
            else
            {
                var error = await Throws<AudioMembershipJournalException>(() => f.Provider.LeaseAsync(inbox, default));
                Require(error.Stage == "completion" && error.InnerException is InvalidOperationException &&
                    f.Read().Checkpoints.SequenceEqual(full.Checkpoints) && f.Read().Pending.Length == 1,
                    "Capacity pressure silently evicted valid grants or concealed its unsettled request.");
            }
        }
    }
}
