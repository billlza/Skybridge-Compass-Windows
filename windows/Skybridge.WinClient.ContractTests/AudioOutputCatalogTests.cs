using System.Runtime.InteropServices;
using Skybridge.WinClient.Services.Audio;
using static Skybridge.WinClient.Services.Audio.AudioOutputNativeMetadata;

internal static class AudioOutputCatalogTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("output catalog preserves opaque IDs immutable names and explicit VT_EMPTY fallback", () => Run(Snapshots)),
        ("output catalog distinguishes an empty native collection from failure and over-capacity", () => Run(EnumerationBounds)),
        ("output catalog validates variant types Unicode and independent string bounds", () => Run(NamesAndIds)),
        ("output catalog native string reads respect their terminator and exact bound", () => Run(NativeStrings)),
        ("output catalog PROPERTYKEY and PROPVARIANT match native pointer-size layout", () => Run(VariantLayout)),
        ("output catalog preserves read and all cleanup failures with retained owners", () => Run(CleanupFailure)),
        ("output catalog observes cancellation between native calls and releases every owned endpoint", () => Run(CancellationBoundaries)),
        ("output catalog cancellation cannot abandon a noncooperative native read", CancellationDuringRead)
    ];
    private static Task Run(Action action) { action(); return Task.CompletedTask; }

    // Only the pure metadata and ownership pipeline is exercised here. Production
    // MMDevice/PROPVARIANT calls still require a Windows native acceptance run.
    private sealed class Enumeration(params Endpoint[] endpoints) : IAudioOutputCatalogEnumeration
    {
        internal uint? CountOverride;
        internal Exception? CountFailure, DisposeFailure;
        internal Action? OnCount;
        internal int DisposeCalls, EndpointCalls, ThreadId;
        internal bool WrongThread;
        internal void Touch()
        {
            int current = Environment.CurrentManagedThreadId;
            if (ThreadId == 0) ThreadId = current;
            if (ThreadId != current) WrongThread = true;
        }
        public uint GetCount() { Touch(); OnCount?.Invoke(); if (CountFailure is { } failure) throw failure; return CountOverride ?? (uint)endpoints.Length; }
        public IAudioOutputCatalogEndpoint GetEndpoint(uint index)
        { Touch(); EndpointCalls++; var endpoint = endpoints[checked((int)index)]; endpoint.Parent = this; return endpoint; }
        public void Dispose() { Touch(); DisposeCalls++; if (DisposeFailure is { } failure) throw failure; }
    }
    private sealed class Endpoint(string id = "{opaque-ID}", string name = "Speakers") : IAudioOutputCatalogEndpoint
    {
        internal Enumeration? Parent;
        internal string Id = id;
        internal AudioOutputName Name = AudioOutputName.FromVariant(31, name);
        internal Exception? NameFailure, DisposeFailure;
        internal Action? OnId, OnName;
        internal int DisposeCalls, NameCalls;
        public string ReadId() { Parent?.Touch(); OnId?.Invoke(); return Id; }
        public AudioOutputName ReadName() { Parent?.Touch(); NameCalls++; OnName?.Invoke(); if (NameFailure is { } failure) throw failure; return Name; }
        public void Dispose() { Parent?.Touch(); DisposeCalls++; if (DisposeFailure is { } failure) throw failure; }
    }

    private static void Snapshots()
    {
        var first = new Endpoint("ID:Case/A", "扬声器 🎵");
        var second = new Endpoint("id:case/a") { Name = AudioOutputName.FromVariant(0, null) };
        var owner = new Enumeration(first, second);
        var result = AudioOutputCatalog.Read(() => owner, default);
        Require(result.Count == 2 && result[0].EndpointId == "ID:Case/A" && result[1].EndpointId == "id:case/a",
            "Catalog parsed or case-folded opaque endpoint IDs.");
        Require(result[0].DisplayName == "扬声器 🎵" && !result[0].IsNameMissing && result[1].DisplayName == second.Id && result[1].IsNameMissing,
            "Friendly-name absence was not explicitly distinguished from a real name.");
        first.Id = "replaced"; first.Name = AudioOutputName.FromVariant(31, "changed");
        Require(result[0].EndpointId == "ID:Case/A" && result[0].DisplayName == "扬声器 🎵", "Returned snapshot retained mutable endpoint metadata.");
        Throws<NotSupportedException>(() => ((IList<AudioOutputEndpoint>)result).Clear());
        Require(owner.DisposeCalls == 1 && first.DisposeCalls == 1 && second.DisposeCalls == 1 && !owner.WrongThread,
            "Successful catalog did not release each owner once on the reading thread.");
    }
    private static void EnumerationBounds()
    {
        var empty = new Enumeration();
        Require(AudioOutputCatalog.Read(() => empty, default).Count == 0 && empty.DisposeCalls == 1, "A genuinely empty collection was not valid.");
        var oversized = new Enumeration { CountOverride = AudioOutputCatalog.MaximumEndpoints + 1 };
        Throws<InvalidDataException>(() => AudioOutputCatalog.Read(() => oversized, default));
        Require(oversized.EndpointCalls == 0 && oversized.DisposeCalls == 1, "Over-capacity native count caused unbounded item reads.");
        var native = new IOException("native enumeration failed"); var failed = new Enumeration { CountFailure = native };
        Require(ReferenceEquals(native, Throws<IOException>(() => AudioOutputCatalog.Read(() => failed, default))) && failed.DisposeCalls == 1,
            "Native failure became an empty collection or lost its identity.");
        var duplicate = new Enumeration(new Endpoint("same"), new Endpoint("same"));
        Throws<InvalidDataException>(() => AudioOutputCatalog.Read(() => duplicate, default));
        Require(duplicate.DisposeCalls == 1, "Duplicate identity failed without releasing enumeration.");
        Require(ReferenceEquals(native, Throws<IOException>(() => AudioOutputCatalog.Read(() => throw native, default))), "Factory failure became empty success.");
    }
    private static void NamesAndIds()
    {
        var text = AudioOutputName.FromVariant(31, "Output");
        foreach (string id in new[] { "", " ", "bad\0id", "\ud800", new string('x', AudioOutputEndpoint.MaximumEndpointIdCharacters + 1),
            new string('é', AudioOutputEndpoint.MaximumEndpointIdUtf8Bytes / 2 + 1) })
            Throws<InvalidDataException>(() => AudioOutputEndpoint.FromNative(id, text));
        foreach (string name in new[] { "", " ", "bad\0name", "\ud800", new string('x', AudioOutputEndpoint.MaximumNameCharacters + 1) })
            Throws<InvalidDataException>(() => AudioOutputEndpoint.FromNative("id", AudioOutputName.FromVariant(31, name)));
        Throws<InvalidDataException>(() => AudioOutputName.FromVariant(8, "BSTR is not LPWSTR"));
        Throws<InvalidDataException>(() => AudioOutputName.FromVariant(31, null));
        Throws<InvalidDataException>(() => AudioOutputName.FromVariant(0, "inconsistent"));
        Throws<InvalidDataException>(() => AudioOutputEndpoint.FromNative("id", default));
        Require(AudioOutputEndpoint.FromNative(new string('x', AudioOutputEndpoint.MaximumEndpointIdCharacters), text).EndpointId.Length == AudioOutputEndpoint.MaximumEndpointIdCharacters,
            "The documented inclusive ID bound was rejected.");
    }
    private static void NativeStrings()
    {
        foreach (string value in new[] { "", "é🎵", new string('x', 16) })
        {
            var pointer = Marshal.StringToCoTaskMemUni(value);
            try { Require(ReadBoundedOutputString(pointer, 16) == value, "Native UTF-16 string was changed."); }
            finally { Marshal.FreeCoTaskMem(pointer); }
        }
        var tooLong = Marshal.StringToCoTaskMemUni(new string('x', 17));
        try { Throws<InvalidDataException>(() => ReadBoundedOutputString(tooLong, 16)); }
        finally { Marshal.FreeCoTaskMem(tooLong); }
        Throws<InvalidDataException>(() => ReadBoundedOutputString(IntPtr.Zero, 16));
    }
    private static void VariantLayout()
    {
        Require(Marshal.SizeOf<OutputPropertyKey>() == 20 && Marshal.OffsetOf<OutputPropertyKey>(nameof(OutputPropertyKey.PropertyId)).ToInt32() == 16,
            "PROPERTYKEY does not match GUID plus DWORD.");
        Require(Marshal.SizeOf<OutputPropertyVariant>() == (IntPtr.Size == 8 ? 24 : 16) &&
            Marshal.OffsetOf<OutputPropertyVariant>(nameof(OutputPropertyVariant.Value)).ToInt32() == 8 &&
            Marshal.OffsetOf<OutputPropertyVariantData>(nameof(OutputPropertyVariantData.Pointer)).ToInt32() == 0,
            "PROPVARIANT lost its reserved header, native union size or pointer offset.");
    }
    private static void CleanupFailure()
    {
        var read = new IOException("property read failed"); var closeItem = new IOException("endpoint release failed"); var closeCollection = new IOException("enumeration release failed");
        var endpoint = new Endpoint { NameFailure = read, DisposeFailure = closeItem };
        var owner = new Enumeration(endpoint) { DisposeFailure = closeCollection };
        var failure = Throws<AudioOutputCatalogCleanupException>(() => AudioOutputCatalog.Read(() => owner, default));
        Require(failure.InnerExceptions.Count == 3 && ReferenceEquals(failure.InnerExceptions[0], read) &&
            failure.InnerExceptions.Contains(closeItem) && failure.InnerExceptions.Contains(closeCollection), "Read or cleanup cause was lost.");
        Require(failure.RetainedOwners.Count == 2 && ReferenceEquals(failure.RetainedOwners[0], endpoint) && ReferenceEquals(failure.RetainedOwners[1], owner),
            "Unconfirmed native owners were not retained for the host.");
        Require(endpoint.DisposeCalls == 1 && owner.DisposeCalls == 1, "Failure cleanup was skipped or blindly retried.");
        var successfulRead = new Endpoint { DisposeFailure = closeItem }; var successfulOwner = new Enumeration(successfulRead);
        var cleanupOnly = Throws<AudioOutputCatalogCleanupException>(() => AudioOutputCatalog.Read(() => successfulOwner, default));
        Require(cleanupOnly.InnerExceptions.Count == 1 && ReferenceEquals(cleanupOnly.InnerExceptions[0], closeItem) && successfulOwner.DisposeCalls == 1,
            "Successful metadata reading concealed a failed release.");
    }
    private static void CancellationBoundaries()
    {
        using var before = new CancellationTokenSource(); before.Cancel(); int opens = 0;
        var error = Throws<OperationCanceledException>(() => AudioOutputCatalog.Read(() => { opens++; return new Enumeration(); }, before.Token));
        Require(opens == 0 && error.CancellationToken == before.Token, "Pre-canceled enumeration touched native state.");
        using var duringCount = new CancellationTokenSource(); var count = new Enumeration(new Endpoint()) { OnCount = duringCount.Cancel };
        Throws<OperationCanceledException>(() => AudioOutputCatalog.Read(() => count, duringCount.Token));
        Require(count.EndpointCalls == 0 && count.DisposeCalls == 1, "Count cancellation leaked the owner or started another native call.");
        using var duringId = new CancellationTokenSource(); var endpoint = new Endpoint { OnId = duringId.Cancel }; var owner = new Enumeration(endpoint);
        Throws<OperationCanceledException>(() => AudioOutputCatalog.Read(() => owner, duringId.Token));
        Require(endpoint.NameCalls == 0 && endpoint.DisposeCalls == 1 && owner.DisposeCalls == 1, "ID cancellation started properties or lost cleanup.");
        using var cleanupCancel = new CancellationTokenSource(); var release = new IOException("canceled endpoint release failed");
        var canceledEndpoint = new Endpoint { OnId = cleanupCancel.Cancel, DisposeFailure = release };
        var aggregate = Throws<AudioOutputCatalogCleanupException>(() => AudioOutputCatalog.Read(() => new Enumeration(canceledEndpoint), cleanupCancel.Token));
        Require(aggregate.InnerExceptions[0] is OperationCanceledException canceled && canceled.CancellationToken == cleanupCancel.Token &&
            aggregate.InnerExceptions.Contains(release), "Cleanup failure swallowed the original cancellation witness.");
    }
    private static async Task CancellationDuringRead()
    {
        using var cancel = new CancellationTokenSource(); using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var endpoint = new Endpoint { OnName = () => { entered.TrySetResult(); release.Wait(); } }; var owner = new Enumeration(endpoint);
        var pending = Task.Run(() => AudioOutputCatalog.Read(() => owner, cancel.Token));
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); cancel.Cancel();
            Require(!pending.IsCompleted && endpoint.DisposeCalls == 0 && owner.DisposeCalls == 0,
                "Cancellation abandoned a blocked native read or released its owner from another thread.");
        }
        finally { release.Set(); }
        var error = await ThrowsAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(2)));
        Require(error.CancellationToken == cancel.Token && endpoint.DisposeCalls == 1 && owner.DisposeCalls == 1 && !owner.WrongThread,
            "Late native return did not preserve cancellation and same-thread complete cleanup.");
    }
    private static T Throws<T>(Action action) where T : Exception
    { try { action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new Exception($"Expected {typeof(T).Name}."); }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
