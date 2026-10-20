using System.Collections.Immutable;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;

internal static class UsbPeerDiscoveryTests
{
    internal static IReadOnlyList<(string Name, Func<Task> Run)> Cases
    {
        get
        {
            var cases = new List<(string, Func<Task>)>
            {
                ("USB discovery canonical transcripts match real Apple Unicode signature vectors", CanonicalVectors),
                ("USB discovery rejects changed fields nonce expiry and malformed identities before publication", Rejections),
                ("USB discovery wire rejects duplicate missing unknown and invalid UTF8 fields", WireRejections),
                ("USB pairing lookup binds exact saved keys without granting a connected state", Pairing),
                ("USB discovery distinguishes an empty bus from unavailable service and excessive devices", ServiceStates),
                ("USB discovery preserves per-device failures and pairing-store failures", DeviceStates),
                ("USB discovery bounds concurrency and rejects duplicated protocol identities", BoundedScan),
                ("USB scanner cancellation drains actual inspections and rejects late results", CancelAndDrain)
            };
            if (OperatingSystem.IsWindows())
            {
                cases.Add(("Windows verifies five real Apple ML-DSA USB discovery signatures", NativeSignatures));
                cases.Add(("Windows USB discovery completes the mux exchange and native signed peer verification", NativeUsbDiscoveryFixture.RoundTrip));
            }
            return cases;
        }
    }
    private const string Udid = "00008132-0000000000000001";
    private sealed record Vector(string Name, long NowMilliseconds, byte[] RequestWire, byte[] ResponseWire, byte[] SigningData);
    private static Vector[] Vectors() => JsonSerializer.Deserialize<Vector[]>(
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "usb-peer-discovery-v1", "apple-vectors.json")),
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new InvalidDataException("Missing Apple vectors.");
    private static UsbPeerDiscoveryRequest Request(Vector vector) =>
        LanBootstrapWire.Decode<UsbPeerDiscoveryRequest>(vector.RequestWire, "usbPeerDiscoveryRequest");
    private static UsbPeerInspection Inspection(string udid = Udid)
    {
        var vector = Vectors()[0];
        // Fixture attestation for scanner/matcher tests, not a cryptographic verifier:
        // exactly one existing Apple transcript, key and signature can be accepted.
        return UsbPeerInspection.Verify(udid, UsbPeerDiscoveryWire.Decode(vector.ResponseWire), Request(vector),
            DateTimeOffset.FromUnixTimeMilliseconds(vector.NowMilliseconds), (identity, preimage, signature) =>
            {
                var expected = UsbPeerDiscoveryWire.Decode(vector.ResponseWire);
                if (!preimage.AsSpan().SequenceEqual(vector.SigningData) ||
                    !signature.AsSpan().SequenceEqual(expected.Signature.AsSpan()) ||
                    !identity.PublicKey.AsSpan().SequenceEqual(expected.Identity.PublicKey.AsSpan()))
                    throw new CryptographicException("Fixture attestation differs.");
            });
    }
    private static Task CanonicalVectors()
    {
        var vectors = Vectors(); Require(vectors.Length == 5, "Expected all five Apple-produced vectors.");
        foreach (var vector in vectors)
        {
            var response = UsbPeerDiscoveryWire.Decode(vector.ResponseWire);
            UsbPeerDiscoveryWire.Validate(response, Request(vector), DateTimeOffset.FromUnixTimeMilliseconds(vector.NowMilliseconds));
            Require(UsbPeerDiscoveryWire.SigningData(response).AsSpan().SequenceEqual(vector.SigningData),
                $"Canonical transcript differs for fixture {Array.IndexOf(vectors, vector)}.");
            Require(response.Name == vector.Name, "Signed presentation changed during decoding.");
        }
        return Task.CompletedTask;
    }
    private static Task NativeSignatures()
    {
        Require(MLDsa.IsSupported, "Windows native ML-DSA verification is required.");
        foreach (var vector in Vectors())
        {
            var response = UsbPeerDiscoveryWire.Decode(vector.ResponseWire);
            var now = DateTimeOffset.FromUnixTimeMilliseconds(vector.NowMilliseconds);
            _ = UsbPeerInspection.Verify(Udid, response, Request(vector), now, UsbPeerDiscoveryWire.VerifyNativeSignature);
            foreach (var changed in new[]
            {
                response with { Name = "Different device" }, response with { Platform = "macos" },
                response with { Identity = response.Identity with { DeviceID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" } }
            })
                Throws<LanPibRejectedException>(() => UsbPeerInspection.Verify(Udid, changed, Request(vector), now,
                    UsbPeerDiscoveryWire.VerifyNativeSignature));
        }
        Console.WriteLine("USB native Apple signature vectors verified: 5");
        return Task.CompletedTask;
    }
    private static Task Rejections()
    {
        var vector = Vectors()[0]; var response = UsbPeerDiscoveryWire.Decode(vector.ResponseWire);
        var request = Request(vector); var now = DateTimeOffset.FromUnixTimeMilliseconds(vector.NowMilliseconds);
        int verificationCalls = 0;
        foreach (var changed in new[]
        {
            response with { Request = request with { Nonce = Guid.NewGuid() } },
            response with { Request = request with { Version = 2 } },
            response with { Name = "" }, response with { Name = new string('é', 65) },
            response with { Name = "hidden\u202Ename" }, response with { Name = "line\nbreak" },
            response with { Platform = "windows" }, response with { Signature = ImmutableArray<byte>.Empty },
            response with { Signature = ImmutableArray.Create(new byte[8193]) },
            response with { Identity = response.Identity with { DeviceID = response.Identity.DeviceID.ToUpperInvariant() } },
            response with { Identity = response.Identity with { Fingerprint = new string('0', 64) } },
            response with { Identity = response.Identity with { PublicKey = ImmutableArray.Create(new byte[1951]) } }
        })
            Throws<InvalidDataException>(() => UsbPeerInspection.Verify(Udid, changed, request, now, (_, _, _) => verificationCalls++));
        foreach (var time in new[] { now.AddMilliseconds(30_001), now.AddMilliseconds(-5_001) })
            Throws<InvalidDataException>(() => UsbPeerInspection.Verify(Udid, response, request, time, (_, _, _) => verificationCalls++));
        Throws<NotSupportedException>(() => UsbPeerInspection.Verify(Udid,
            response with { Identity = response.Identity with { Algorithm = "ML-DSA-87" } }, request, now, (_, _, _) => verificationCalls++));
        Require(verificationCalls == 0, "Invalid binding reached native signature verification.");
        return Task.CompletedTask;
    }
    private static Task WireRejections()
    {
        var wire = Encoding.UTF8.GetString(Vectors()[0].ResponseWire);
        foreach (var changed in new[]
        {
            wire.Replace("\"version\":1", "\"version\":1,\"version\":1", StringComparison.Ordinal),
            wire.Replace("\"version\":1", "\"other\":1", StringComparison.Ordinal),
            wire.Replace("\"version\":1", "\"version\":1,\"other\":1", StringComparison.Ordinal),
            wire.Replace("\"version\":1", "\"version\":1.5", StringComparison.Ordinal),
            wire.Replace("\"name\":", "\"name\":null,\"name\":", StringComparison.Ordinal)
        })
            Throws<JsonException>(() => UsbPeerDiscoveryWire.Decode(Encoding.UTF8.GetBytes(changed)));
        Throws<DecoderFallbackException>(() => UsbPeerDiscoveryWire.Decode([0xff]));
        Throws<InvalidDataException>(() => UsbPeerDiscoveryWire.Decode(new byte[UsbPeerDiscoveryWire.MaximumFrameBytes + 1]));
        return Task.CompletedTask;
    }
    private static Task Pairing()
    {
        var inspection = Inspection(); var identity = inspection.Response.Identity;
        const string local = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        var saved = RemoteControlPairingMaterial.CreateProtocolIdentity(identity.DeviceID, "Old name", identity.PublicKey.AsSpan());
        Require(UsbPeerPairingMatcher.Match(inspection, local, [saved]) == UsbPeerPairingState.Paired,
            "A renamed device with the exact saved key did not match.");
        Require(UsbPeerPairingMatcher.Match(inspection, local, []) == UsbPeerPairingState.Unpaired, "Public signature granted local pairing.");
        var different = RemoteControlPairingMaterial.CreateProtocolIdentity(identity.DeviceID, inspection.Response.Name, new byte[1952]);
        Require(UsbPeerPairingMatcher.Match(inspection, local, [different]) == UsbPeerPairingState.IdentityConflict, "Changed key matched by name or ID.");
        Require(UsbPeerPairingMatcher.Match(inspection, identity.DeviceID, [saved]) == UsbPeerPairingState.IdentityConflict, "Local identity was accepted as a peer.");
        Require(saved.IsProtocolIdentityOnly, "Inspection created or imported KEM authority.");
        return Task.CompletedTask;
    }
    private static async Task ServiceStates()
    {
        await using (var scanner = new UsbPeerScanner(_ => Task.FromResult<IReadOnlyList<UsbMuxDevice>>([]),
            (_, _) => throw new InvalidOperationException("Empty bus must not probe."), null))
        {
            var result = await scanner.ScanAsync(); Require(result.Entries.Count == 0 && result.Failure is null, "Legitimate empty bus failed.");
        }
        var original = new SocketException((int)SocketError.ConnectionRefused);
        await using (var scanner = new UsbPeerScanner(_ => Task.FromException<IReadOnlyList<UsbMuxDevice>>(original),
            (_, _) => throw new InvalidOperationException("Unavailable service must not probe."), null))
        {
            var result = await scanner.ScanAsync();
            Require(result.Entries.Count == 0 && ReferenceEquals(result.Failure, original) &&
                result.FailureStatus == UsbPeerScanner.ServiceUnavailable, "Service failure became an empty success.");
        }
        await using (var scanner = new UsbPeerScanner(_ => Task.FromResult<IReadOnlyList<UsbMuxDevice>>(
            Enumerable.Range(1, 9).Select(index => Device(index)).ToArray()),
            (_, _) => throw new InvalidOperationException("Excessive bus must not probe."), null))
        {
            var result = await scanner.ScanAsync();
            Require(result.Failure is InvalidDataException && result.FailureStatus == UsbPeerScanner.TooManyDevices, "Oversized scan was truncated or accepted.");
        }
    }
    private static async Task DeviceStates()
    {
        var storageFailure = new IOException("Injected private pairing-store read failure.");
        await using var scanner = new UsbPeerScanner(_ => Task.FromResult<IReadOnlyList<UsbMuxDevice>>([Device(1), Device(2)]),
            (udid, _) => udid == Device(1).Udid ? Task.FromResult(Inspection(udid)) :
                Task.FromException<UsbPeerInspection>(new UsbMuxException(UsbMuxFailure.PortUnavailable)),
            (_, _) => Task.FromException<UsbPeerPairingState>(storageFailure));
        var result = await scanner.ScanAsync();
        Require(result.Entries[0].Inspection is not null && result.Entries[0].Status == UsbPeerScanner.PairingUnavailable &&
            ReferenceEquals(result.Entries[0].Failure, storageFailure), "Failed pairing read pretended unpaired or erased signed identity.");
        Require(result.Entries[1].Inspection is null && result.Entries[1].Status == UsbPeerScanner.OpenApp, "Closed port became a verified peer.");
    }
    private static async Task BoundedScan()
    {
        int active = 0, maximum = 0;
        var maximumGate = new object();
        var bothEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var scanner = new UsbPeerScanner(_ => Task.FromResult<IReadOnlyList<UsbMuxDevice>>(
            Enumerable.Range(1, 5).Select(index => Device(index)).ToArray()), async (udid, token) =>
            {
                int current = Interlocked.Increment(ref active);
                lock (maximumGate) maximum = Math.Max(maximum, current);
                if (current == 2) bothEntered.TrySetResult();
                try { await release.Task.WaitAsync(token); return Inspection(udid); }
                finally { Interlocked.Decrement(ref active); }
            }, (_, _) => Task.FromResult(UsbPeerPairingState.Paired));
        var scan = scanner.ScanAsync();
        try { await bothEntered.Task.WaitAsync(TimeSpan.FromSeconds(3)); Require(active == 2, "Wrong scan concurrency."); }
        finally { release.TrySetResult(); }
        var result = await scan.WaitAsync(TimeSpan.FromSeconds(4));
        Require(maximum == 2 && active == 0 && result.Entries.Count == 5 &&
            result.Entries.All(entry => entry.Status == UsbPeerScanner.DuplicateIdentity && entry.Failure is not null),
            "Scan exceeded capacity or presented cloned device identities as paired.");
    }
    private static async Task CancelAndDrain()
    {
        int pairingCalls = 0;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var scanner = new UsbPeerScanner(_ => Task.FromResult<IReadOnlyList<UsbMuxDevice>>([Device(1)]),
            async (udid, token) =>
            {
                using var registration = token.Register(() => canceled.TrySetResult());
                entered.TrySetResult();
                await release.Task; // Deliberately noncooperative provider must remain owned until actual return.
                return Inspection(udid);
            }, (_, _) => { Interlocked.Increment(ref pairingCalls); return Task.FromResult(UsbPeerPairingState.Paired); });
        var scan = scanner.ScanAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var close = scanner.DisposeAsync().AsTask(); await canceled.Task.WaitAsync(TimeSpan.FromSeconds(3));
        try { Require(!close.IsCompleted, "Closing abandoned the active provider."); }
        finally { release.TrySetResult(); }
        await ThrowsAsync<OperationCanceledException>(() => scan);
        await close.WaitAsync(TimeSpan.FromSeconds(3));
        Require(pairingCalls == 0, "Canceled inspection reached the saved-pairing lookup.");
        await scanner.DisposeAsync();
        await ThrowsAsync<ObjectDisposedException>(() => scanner.ScanAsync());
    }
    private static UsbMuxDevice Device(int index) => new((uint)index, $"00008132-{index:D16}", 4779);
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static void Throws<T>(Action operation) where T : Exception
    { try { operation(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static async Task ThrowsAsync<T>(Func<Task> operation) where T : Exception
    { try { await operation(); } catch (T) { return; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
}
