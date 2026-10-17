using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Skybridge.WinClient.Services.Audio;

// An immutable selection snapshot, not a format-support claim or a persistent
// default-device preference. Endpoint IDs stay opaque and are never normalized.
internal sealed record AudioOutputEndpoint
{
    internal const int MaximumEndpointIdCharacters = 4096;
    internal const int MaximumEndpointIdUtf8Bytes = 4096;
    internal const int MaximumNameCharacters = 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private AudioOutputEndpoint(string endpointId, string displayName, bool nameMissing)
    { EndpointId = endpointId; DisplayName = displayName; IsNameMissing = nameMissing; }
    internal string EndpointId { get; }
    internal string DisplayName { get; }
    internal bool IsNameMissing { get; }

    internal static AudioOutputEndpoint FromNative(string endpointId, AudioOutputName name)
    {
        ValidateText(endpointId, MaximumEndpointIdCharacters, "endpoint ID");
        if (StrictUtf8.GetByteCount(endpointId) > MaximumEndpointIdUtf8Bytes)
            throw new InvalidDataException("The output endpoint ID exceeds the playback-approval resource limit.");
        if (name.IsMissing) return new(endpointId, endpointId, true);
        var value = name.Value ?? throw new InvalidDataException("The output name is missing without VT_EMPTY.");
        ValidateText(value, MaximumNameCharacters, "endpoint name");
        return new(endpointId, value, false);
    }
    private static void ValidateText(string value, int limit, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > limit || value.Contains('\0'))
            throw new InvalidDataException($"The audio {field} is empty, malformed or too long.");
        try { _ = StrictUtf8.GetByteCount(value); }
        catch (EncoderFallbackException error) { throw new InvalidDataException($"The audio {field} is not valid Unicode.", error); }
    }
}

internal readonly record struct AudioOutputName
{
    private AudioOutputName(string? value, bool missing) { Value = value; IsMissing = missing; }
    internal string? Value { get; }
    internal bool IsMissing { get; }
    internal static AudioOutputName FromVariant(ushort variantType, string? value) => variantType switch
    {
        0 when value is null => new(null, true), // Only VT_EMPTY permits the explicit ID display fallback.
        31 when value is not null => new(value, false), // VT_LPWSTR
        _ => throw new InvalidDataException("The output friendly-name property has an unsupported or inconsistent value type.")
    };
}

// Pure ABI/storage helpers: no COM creation or platform calls. The union includes
// BLOB so PROPVARIANT has its complete native size on both 32- and 64-bit targets.
internal static class AudioOutputNativeMetadata
{
    internal static string ReadBoundedOutputString(IntPtr pointer, int maximumCharacters)
    {
        if (pointer == IntPtr.Zero || maximumCharacters <= 0 || maximumCharacters > AudioOutputEndpoint.MaximumEndpointIdCharacters)
            throw new InvalidDataException("Native output string has no valid bounded storage.");
        var characters = new char[maximumCharacters];
        for (int index = 0; index <= maximumCharacters; index++)
        {
            char value = (char)(ushort)Marshal.ReadInt16(pointer, checked(index * sizeof(char)));
            if (value == '\0') return new string(characters, 0, index);
            if (index == maximumCharacters) break;
            characters[index] = value;
        }
        throw new InvalidDataException("Native output string exceeds the catalog resource limit.");
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct OutputPropertyKey { internal Guid FormatId; internal uint PropertyId; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct OutputPropertyBlob { internal uint Size; internal IntPtr Data; }
    [StructLayout(LayoutKind.Explicit)]
    internal struct OutputPropertyVariantData
    {
        [FieldOffset(0)] internal IntPtr Pointer;
        [FieldOffset(0)] internal long Integer;
        [FieldOffset(0)] internal OutputPropertyBlob Blob;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct OutputPropertyVariant
    {
        internal ushort Type, Reserved1, Reserved2, Reserved3;
        internal OutputPropertyVariantData Value;
    }
}

internal interface IAudioOutputCatalogEnumeration : IDisposable
{
    uint GetCount();
    IAudioOutputCatalogEndpoint GetEndpoint(uint index);
}
internal interface IAudioOutputCatalogEndpoint : IDisposable
{
    string ReadId();
    AudioOutputName ReadName();
}

// Cleanup failure is not an empty catalog. Keep the failed owners reachable so
// the host can block another operation instead of treating a second close as success.
internal sealed class AudioOutputCatalogCleanupException : AggregateException
{
    internal AudioOutputCatalogCleanupException(IEnumerable<Exception> errors, IEnumerable<object> retainedOwners)
        : base("Audio output enumeration failed to confirm native resource release.", errors)
    { RetainedOwners = Array.AsReadOnly(retainedOwners.ToArray()); }
    internal IReadOnlyList<object> RetainedOwners { get; }
}

internal static class AudioOutputCatalog
{
    internal const uint MaximumEndpoints = 128;

    // Every operation and cleanup is synchronous on this caller. Cancellation never
    // detaches a still-running native call. Only immutable strings cross this boundary.
    internal static IReadOnlyList<AudioOutputEndpoint> Read(Func<IAudioOutputCatalogEnumeration> open, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(open);
        cancellationToken.ThrowIfCancellationRequested();
        IAudioOutputCatalogEnumeration? enumeration = null;
        var outputs = new List<AudioOutputEndpoint>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        Exception? failure = null;
        var cleanup = new List<Exception>();
        var retained = new List<object>();
        try
        {
            enumeration = open() ?? throw new InvalidOperationException("Native output enumeration returned no owner.");
            cancellationToken.ThrowIfCancellationRequested();
            uint count = enumeration.GetCount();
            cancellationToken.ThrowIfCancellationRequested();
            if (count > MaximumEndpoints) throw new InvalidDataException("The active audio output count exceeds the bounded catalog capacity.");
            for (uint index = 0; index < count; index++)
            {
                IAudioOutputCatalogEndpoint? endpoint = null;
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    endpoint = enumeration.GetEndpoint(index) ?? throw new InvalidOperationException("Native endpoint lookup returned no owner.");
                    cancellationToken.ThrowIfCancellationRequested();
                    string id = endpoint.ReadId();
                    cancellationToken.ThrowIfCancellationRequested();
                    var name = endpoint.ReadName();
                    cancellationToken.ThrowIfCancellationRequested();
                    var snapshot = AudioOutputEndpoint.FromNative(id, name);
                    if (!ids.Add(snapshot.EndpointId)) throw new InvalidDataException("Native output enumeration returned a duplicate endpoint ID.");
                    outputs.Add(snapshot);
                }
                catch (Exception error) { failure = error; }
                finally { if (endpoint is not null) Close(endpoint); }
                if (failure is not null || cleanup.Count != 0) break;
            }
        }
        catch (Exception error) { failure = error; }
        finally { if (enumeration is not null) Close(enumeration); }
        if (cleanup.Count != 0)
            throw new AudioOutputCatalogCleanupException(failure is null ? cleanup : new[] { failure }.Concat(cleanup), retained);
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        cancellationToken.ThrowIfCancellationRequested();
        return Array.AsReadOnly(outputs.ToArray());

        void Close(IDisposable owner)
        {
            try { owner.Dispose(); }
            catch (Exception error) { cleanup.Add(error); retained.Add(owner); }
        }
    }
}
