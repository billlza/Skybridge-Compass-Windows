using System.Net.Sockets;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services.Connection;

internal enum UsbPeerPairingState { Unpaired, Paired, IdentityConflict }
internal sealed record UsbPeerScanEntry(UsbMuxDevice Device, UsbPeerInspection? Inspection, string Status, Exception? Failure);
internal sealed record UsbPeerScanReport(IReadOnlyList<UsbPeerScanEntry> Entries, string? FailureStatus, Exception? Failure);

/// <summary>One bounded read-only scan. Public signatures and saved pins never create a session grant.</summary>
internal sealed class UsbPeerScanner : IAsyncDisposable
{
    internal const string Paired = "SkyBridge paired; not connected";
    internal const string Unpaired = "SkyBridge found; pairing required";
    internal const string IdentityConflict = "SkyBridge identity differs from saved pairing";
    internal const string PairingUnavailable = "SkyBridge found; saved pairing could not be read";
    internal const string OpenApp = "Open SkyBridge on the connected Apple device";
    internal const string Unplugged = "USB device is no longer available";
    internal const string InvalidIdentity = "SkyBridge identity verification failed";
    internal const string Unsupported = "SkyBridge USB signature support is unavailable";
    internal const string TimedOut = "SkyBridge USB device did not respond in time";
    internal const string Failed = "SkyBridge USB inspection failed";
    internal const string ServiceUnavailable = "Apple USB connection service is unavailable";
    internal const string TooManyDevices = "Connect at most eight Apple USB devices to inspect SkyBridge";
    internal const string PairingNotLoaded = "SkyBridge found; pairing status is not loaded";
    internal const string DuplicateIdentity = "Multiple USB devices share one SkyBridge identity";

    private readonly Func<CancellationToken, Task<IReadOnlyList<UsbMuxDevice>>> _enumerate;
    private readonly Func<string, CancellationToken, Task<UsbPeerInspection>> _inspect;
    private readonly Func<UsbPeerInspection, CancellationToken, Task<UsbPeerPairingState>>? _pairing;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _scan = new(1, 1);
    private readonly SemaphoreSlim _close = new(1, 1);
    private volatile bool _disposed;
    private Exception? _cancellationFailure;
    private readonly object _failureGate = new();
    private Exception? _unreleasedFailure;

    internal UsbPeerScanner(Func<CancellationToken, Task<IReadOnlyList<UsbMuxDevice>>> enumerate,
        Func<string, CancellationToken, Task<UsbPeerInspection>> inspect,
        Func<UsbPeerInspection, CancellationToken, Task<UsbPeerPairingState>>? pairing)
    { _enumerate = enumerate; _inspect = inspect; _pairing = pairing; }

    internal static UsbPeerScanner Windows(
        Func<UsbPeerInspection, CancellationToken, Task<UsbPeerPairingState>>? pairing)
    {
        var connector = UsbMuxConnector.WindowsService();
        var client = new UsbPeerDiscoveryClient(connector);
        return new(connector.DevicesAsync, client.InspectAsync, pairing);
    }

    internal async Task<UsbPeerScanReport> ScanAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, cancellationToken);
        await _scan.WaitAsync(caller.Token).ConfigureAwait(false);
        try
        {
            lock (_failureGate)
            {
                if (_unreleasedFailure is { } retained)
                    throw new InvalidOperationException("USB inspection has an unreleased native owner.", retained);
            }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(caller.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(40));
            var token = deadline.Token;
            try
            {
                var devices = await _enumerate(token).ConfigureAwait(false);
                if (devices.Count > 8) throw new InvalidDataException(TooManyDevices);
                var entries = new UsbPeerScanEntry[devices.Count];
                await Parallel.ForEachAsync(Enumerable.Range(0, devices.Count),
                    new ParallelOptions { MaxDegreeOfParallelism = 2, CancellationToken = token }, async (index, current) =>
                    {
                        var device = devices[index];
                        UsbPeerInspection inspection;
                        try { inspection = await _inspect(device.Udid, current).ConfigureAwait(false); }
                        catch (OperationCanceledException) when (current.IsCancellationRequested) { throw; }
                        catch (Exception error)
                        {
                            if (ProductBootstrapReleaseException.ContainsUnreleasedOwner(error))
                            {
                                lock (_failureGate)
                                    _unreleasedFailure = _unreleasedFailure is null ? error : new AggregateException(_unreleasedFailure, error);
                            }
                            entries[index] = new(device, null, Classify(error), error); return;
                        }
                        current.ThrowIfCancellationRequested();
                        if (inspection.Udid != device.Udid)
                            throw new InvalidDataException("USB discovery returned a different cable route.");
                        if (_pairing is null) { entries[index] = new(device, inspection, PairingNotLoaded, null); return; }
                        try
                        {
                            var state = await _pairing(inspection, current).ConfigureAwait(false);
                            entries[index] = new(device, inspection, state switch
                            {
                                UsbPeerPairingState.Paired => Paired,
                                UsbPeerPairingState.Unpaired => Unpaired,
                                UsbPeerPairingState.IdentityConflict => IdentityConflict,
                                _ => throw new InvalidDataException("Unknown USB pairing state.")
                            }, null);
                        }
                        catch (OperationCanceledException) when (current.IsCancellationRequested) { throw; }
                        catch (Exception error) { entries[index] = new(device, inspection, PairingUnavailable, error); }
                    }).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                foreach (var duplicate in entries.GroupBy(entry => entry.Inspection?.Response.Identity.DeviceID, StringComparer.Ordinal)
                    .Where(group => group.Key is not null && group.Count() > 1))
                {
                    foreach (var entry in duplicate)
                    {
                        int index = Array.IndexOf(entries, entry);
                        entries[index] = entry with { Status = DuplicateIdentity,
                            Failure = new InvalidDataException("One protocol identity appeared on multiple USB routes.") };
                    }
                }
                return new(entries, null, null);
            }
            catch (OperationCanceledException) when (caller.IsCancellationRequested) { throw; }
            catch (OperationCanceledException error) when (deadline.IsCancellationRequested)
            { return new([], TimedOut, new TimeoutException("USB peer scan exceeded its deadline.", error)); }
            catch (Exception error)
            {
                if (ProductBootstrapReleaseException.ContainsUnreleasedOwner(error))
                {
                    lock (_failureGate) _unreleasedFailure = error;
                }
                var status = error is SocketException ? ServiceUnavailable :
                    error is InvalidDataException { Message: TooManyDevices } ? TooManyDevices : Classify(error);
                return new([], status, error);
            }
        }
        finally { _scan.Release(); }
    }

    private static string Classify(Exception error) => error switch
    {
        UsbMuxException { Failure: UsbMuxFailure.PortUnavailable } => OpenApp,
        UsbMuxException { Failure: UsbMuxFailure.DeviceUnavailable } => Unplugged,
        NotSupportedException => Unsupported,
        TimeoutException => TimedOut,
        LanPibRejectedException or System.Security.Cryptography.CryptographicException or InvalidDataException
            or System.Text.Json.JsonException => InvalidIdentity,
        _ => Failed
    };

    public async ValueTask DisposeAsync()
    {
        await _close.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_disposed)
            {
                try { _lifetime.Cancel(); } catch (Exception error) { _cancellationFailure ??= error; }
                // Retain this owner if a provider has not actually returned.
                // A later close can retry the same drain.
                if (!await _scan.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false))
                {
                    var timeout = new TimeoutException("USB inspection has not released its active operation.");
                    if (_cancellationFailure is { } cancellation)
                        throw new AggregateException(cancellation, timeout);
                    throw timeout;
                }
                try
                {
                    lock (_failureGate)
                    {
                        if (_unreleasedFailure is { } retained)
                            throw new InvalidOperationException("USB native cleanup remains unconfirmed.",
                                _cancellationFailure is null ? retained : new AggregateException(_cancellationFailure, retained));
                    }
                    _disposed = true; _lifetime.Dispose();
                }
                finally { _scan.Release(); }
            }
            if (_cancellationFailure is { } failure)
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
        finally { _close.Release(); }
    }
}
