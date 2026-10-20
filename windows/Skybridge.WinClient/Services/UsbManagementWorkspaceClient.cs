using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Devices.Enumeration;
using Skybridge.WinClient.Services.Connection;

namespace Skybridge.WinClient.Services;

public interface IUsbManagementWorkspaceClient
{
    string BuildInitialStatus();

    string BuildPendingStatus();

    string BuildCompletedStatus(UsbManagementWorkspaceSnapshot snapshot);

    string BuildCompletedStatusMessage();

    Task<UsbManagementWorkspaceSnapshot> BuildReadOnlySnapshotAsync();
}

/// <summary>
/// Read-only USB workspace provider for the Mac-style USB Management screen.
///
/// Enumeration is REAL and in-framework (no extra NuGet package): it uses the
/// WinRT <see cref="DeviceInformation.FindAllAsync(string)"/> projection — already on the
/// app's <c>net10.0-windows10.0.22621.0</c> TFM with TargetPlatformMinVersion
/// <c>10.0.19041.0</c> and already exercised elsewhere
/// (WeatherClient consumes Windows.Devices.Geolocation) — against the
/// <see cref="Windows.Devices.Usb.UsbDevice.GetDeviceSelector()"/> AQS selector, which is
/// what surfaces real Vendor/Product IDs. The DriveInfo removable-volume pass is kept and
/// MERGED in so mass-storage volumes still carry their human label + capacity facts.
///
/// This mirrors the Mac <c>USBCConnectionManager.enumerateUSBDevicesSnapshot()</c> shape:
/// per-device VID/PID/name/serial + a coarse device-type classification + capability chips.
/// It is honest — when nothing is connected the collections come back empty (the view shows
/// the empty state) and no placeholder/fake rows are ever fabricated. Fields that genuinely
/// cannot be read from a given source stay blank rather than carrying invented values.
/// </summary>
public sealed class UsbManagementWorkspaceClient : IUsbManagementWorkspaceClient, IAsyncDisposable
{
    private readonly Func<UsbPeerInspection, CancellationToken, Task<UsbPeerPairingState>>? _pairing;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _refresh = new(1, 1), _close = new(1, 1);
    private UsbPeerScanner? _peers;
    private volatile bool _disposed;
    private Exception? _cancellationFailure;
    private readonly object _candidateGate = new();
    private Dictionary<string, UsbPeerScanEntry> _peerCandidates = new(StringComparer.Ordinal);
    public UsbManagementWorkspaceClient() { }
    internal UsbManagementWorkspaceClient(Func<UsbPeerInspection, CancellationToken, Task<UsbPeerPairingState>> pairing)
    { _pairing = pairing; }

    public string BuildInitialStatus() => DefaultInitialStatus;

    public string BuildPendingStatus() => DefaultPendingStatus;

    public string BuildCompletedStatus(UsbManagementWorkspaceSnapshot snapshot) =>
        BuildDefaultCompletedStatus(snapshot);

    public string BuildCompletedStatusMessage() => DefaultCompletedStatusMessage;

    public static string DefaultInitialStatus { get; } = "Ready";

    public static string DefaultPendingStatus { get; } = "Refreshing...";

    public static string DefaultCompletedStatusMessage { get; } = "USB management workspace updated";

    public static string BuildDefaultCompletedStatus(UsbManagementWorkspaceSnapshot snapshot) =>
        snapshot.SkybridgeFailureStatus ?? $"Last scan {snapshot.CapturedAt:HH:mm:ss} UTC";

    internal UsbPeerInspection RequireEnrollmentTarget(string udid, string expectedFingerprint, string expectedDeviceId) =>
        RequireTarget(udid, expectedFingerprint, expectedDeviceId, UsbPeerScanner.Unpaired);

    internal UsbPeerInspection RequireConnectionTarget(string udid, string expectedFingerprint, string expectedDeviceId) =>
        RequireTarget(udid, expectedFingerprint, expectedDeviceId, UsbPeerScanner.Paired);

    private UsbPeerInspection RequireTarget(string udid, string expectedFingerprint, string expectedDeviceId, string requiredState)
    {
        lock (_candidateGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _lifetime.Token.ThrowIfCancellationRequested();
            if (!_peerCandidates.TryGetValue(udid, out var candidate) || candidate.Status != requiredState ||
                candidate.Inspection is not { } target || target.Response.Identity.Fingerprint != expectedFingerprint ||
                RemoteControlHandshakeBinding.CanonicalDeviceId(target.Response.Identity.DeviceID) != expectedDeviceId)
                throw new InvalidOperationException("Refresh USB devices before using this identity.");
            return target;
        }
    }

    // ---- Vendor allow-lists, mirroring USBCConnectionManager's hardcoded lists ----
    private const ushort AppleVendorId = 0x05AC;

    private static readonly HashSet<ushort> AndroidVendorIds = new()
    {
        0x18D1, 0x04E8, 0x0BB4, 0x22B8, 0x19D2, 0x12D1, 0x0FCE, 0x0489, 0x1004, 0x2717, 0x2A45
    };

    private static readonly HashSet<ushort> StorageVendorIds = new()
    {
        0x0781, 0x0930, 0x058F, 0x090C, 0x13FE, 0x0951, 0x8564, 0x1058, 0x04C5, 0x0480
    };

    // USB instance-path VID/PID, e.g. "USB\VID_05AC&PID_12A8\..." or "...#vid_05ac&pid_12a8#...".
    private static readonly Regex VidPidRegex = new(
        @"VID_(?<vid>[0-9A-Fa-f]{4}).*?PID_(?<pid>[0-9A-Fa-f]{4})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task<UsbManagementWorkspaceSnapshot> BuildReadOnlySnapshotAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _refresh.WaitAsync(_lifetime.Token).ConfigureAwait(false);
        try { return await BuildSnapshotAsync(_lifetime.Token).ConfigureAwait(false); }
        finally { _refresh.Release(); }
    }

    private async Task<UsbManagementWorkspaceSnapshot> BuildSnapshotAsync(CancellationToken token)
    {
        // 1) Real USB-device enumeration via the in-framework WinRT projection.
        var usbDevices = await EnumerateUsbDevicesAsync(token).ConfigureAwait(false);

        // 2) Removable-storage volumes (DriveInfo) — merged so storage volumes keep their
        //    human label + capacity facts. Matched onto a USB device by drive letter where
        //    possible; otherwise surfaced as a standalone storage row.
        var storageVolumes = await Task.Run(EnumerateRemovableVolumes, token).ConfigureAwait(false);

        var devices = MergeDevices(usbDevices, storageVolumes);

        token.ThrowIfCancellationRequested();
        _peers ??= UsbPeerScanner.Windows(_pairing);
        var report = await _peers.ScanAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var candidates = report.Entries
            .Where(entry => (entry.Status is UsbPeerScanner.Unpaired or UsbPeerScanner.Paired) && entry.Failure is null && entry.Inspection is not null)
            .ToDictionary(entry => entry.Device.Udid, entry => entry, StringComparer.Ordinal);
        var items = devices.Select(d => d.ToItem()).ToList();
        foreach (var entry in report.Entries)
        {
            if (entry.Failure is { } failure)
                WindowsRuntimeLog.Write(WindowsLogLevel.Warning, "UsbPeerInspection", failure.GetType().Name);
            var matches = items.Select((item, index) => (item, index)).Where(pair =>
                UsbMuxProtocol.ValidUdid(pair.item.SerialNumber) &&
                pair.item.SerialNumber.Replace("-", "", StringComparison.Ordinal).Equals(
                    entry.Device.Udid.Replace("-", "", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase)).ToArray();
            var name = entry.Inspection?.Response.Name;
            var verified = candidates.TryGetValue(entry.Device.Udid, out var candidate) ? candidate.Inspection : null;
            string? protocolId = verified is null ? null : RemoteControlHandshakeBinding.CanonicalDeviceId(verified.Response.Identity.DeviceID);
            if (string.IsNullOrWhiteSpace(name)) name = null; // Presentation only; signed identity is retained unchanged.
            if (matches.Length == 1)
            {
                var match = matches[0];
                items[match.index] = match.item with
                {
                    Name = name ?? match.item.Name, SkybridgeStatus = entry.Status, IsMfiCertified = false,
                    SkybridgeUdid = verified is null ? null : entry.Device.Udid,
                    SkybridgeFingerprint = verified?.Response.Identity.Fingerprint,
                    SkybridgeDeviceId = protocolId
                };
            }
            else
            {
                // The Apple service supplies the usable route even when a generic
                // WinRT interface is absent or ambiguous. Never bind by display name.
                items.Add(new(name ?? "Apple", "usb:" + entry.Device.Udid, "Apple device",
                    "0x05AC", $"0x{entry.Device.ProductId:X4}", entry.Device.Udid, "USB",
                    ["USB"], "appleMfi", false, entry.Status,
                    verified is null ? null : entry.Device.Udid, verified?.Response.Identity.Fingerprint, protocolId));
            }
        }
        if (report.Failure is { } serviceFailure)
            WindowsRuntimeLog.Write(WindowsLogLevel.Warning, "UsbPeerEnumeration", serviceFailure.GetType().Name);
        var appleCount = items.Count(d => d.DeviceTypeKey == "appleMfi");
        var androidCount = devices.Count(d => d.DeviceTypeKind == UsbDeviceTypeKind.Android);
        var storageCount = devices.Count(d =>
            d.DeviceTypeKind is UsbDeviceTypeKind.ExternalDrive or UsbDeviceTypeKind.FlashDrive);

        var stats = new List<UsbDeviceStat>
        {
            new("Apple Devices", appleCount.ToString(CultureInfo.InvariantCulture), "Connected Apple USB devices"),
            new("Android Devices", androidCount.ToString(CultureInfo.InvariantCulture), "ADB/MTP-class handsets"),
            new("Storage Devices", storageCount.ToString(CultureInfo.InvariantCulture), "External drives + flash media"),
            new("Total Devices", items.Count.ToString(CultureInfo.InvariantCulture), "Connected USB devices")
        };

        token.ThrowIfCancellationRequested();
        lock (_candidateGate) _peerCandidates = candidates;
        return new UsbManagementWorkspaceSnapshot(
            DateTimeOffset.UtcNow,
            stats,
            items, report.FailureStatus);
    }

    public async ValueTask DisposeAsync()
    {
        await _close.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!_disposed)
            {
                try { _lifetime.Cancel(); } catch (Exception error) { _cancellationFailure ??= error; }
                if (!await _refresh.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false))
                {
                    var timeout = new TimeoutException("USB workspace refresh has not released its active operation.");
                    if (_cancellationFailure is { } cancellation) throw new AggregateException(cancellation, timeout);
                    throw timeout;
                }
                try
                {
                    if (_peers is not null) await _peers.DisposeAsync().ConfigureAwait(false);
                    lock (_candidateGate)
                    {
                        _peerCandidates.Clear(); _disposed = true; _lifetime.Dispose();
                    }
                }
                finally { _refresh.Release(); }
            }
            if (_cancellationFailure is { } failure)
                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
        finally { _close.Release(); }
    }

    private static async Task<List<EnumeratedUsbDevice>> EnumerateUsbDevicesAsync(CancellationToken token)
    {
        var results = new List<EnumeratedUsbDevice>();
        try
        {
            // Enumerate all USB peripherals via the GUID_DEVINTERFACE_USB_DEVICE interface-class AQS.
            // (UsbDevice.GetDeviceSelector requires a VID/PID or class, so it can't list "all"; this
            // generic interface AQS lists every USB device, and TryBuildDevice parses VID/PID from
            // each device's instance Id — USB\VID_xxxx&PID_yyyy&... .)
            const string usbDeviceInterfaceClass = "{A5DCBF10-6530-11D2-901F-00C04FB951ED}";
            var selector = $"System.Devices.InterfaceClassGuid:=\"{usbDeviceInterfaceClass}\"";
            var collection = await DeviceInformation
                .FindAllAsync(selector, UsbInformationProperties)
                .AsTask(token)
                .ConfigureAwait(false);

            foreach (var info in collection)
            {
                var device = TryBuildDevice(info);
                if (device is not null)
                {
                    results.Add(device);
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception error) { throw new IOException("USB device enumeration failed.", error); }

        return results;
    }

    private static readonly string[] UsbInformationProperties =
    {
        "System.Devices.DeviceInstanceId",
        "System.ItemNameDisplay"
    };

    private static EnumeratedUsbDevice? TryBuildDevice(DeviceInformation info)
    {
        var instanceId = ReadStringProperty(info, "System.Devices.DeviceInstanceId");
        var source = !string.IsNullOrWhiteSpace(instanceId) ? instanceId : info.Id;

        ushort vendorId = 0;
        ushort productId = 0;
        var match = VidPidRegex.Match(source ?? string.Empty);
        if (match.Success)
        {
            vendorId = ParseHex(match.Groups["vid"].Value);
            productId = ParseHex(match.Groups["pid"].Value);
        }

        var name = !string.IsNullOrWhiteSpace(info.Name)
            ? info.Name
            : ReadStringProperty(info, "System.ItemNameDisplay");
        if (string.IsNullOrWhiteSpace(name))
        {
            name = "USB device";
        }

        var serial = ExtractSerial(instanceId);
        var kind = ClassifyDevice(vendorId, name);
        // Vendor/type hints cannot establish accessory certification or peer trust.
        var isMfi = false;

        var deviceId = vendorId != 0 || productId != 0
            ? string.Create(CultureInfo.InvariantCulture, $"{vendorId:X4}:{productId:X4}{(string.IsNullOrEmpty(serial) ? string.Empty : ":" + serial)}")
            : (instanceId ?? info.Id ?? name);

        var capabilities = new List<string> { "USB" };
        if (info.IsEnabled)
        {
            capabilities.Add("Connected");
        }

        return new EnumeratedUsbDevice(
            DeviceId: deviceId,
            Name: name,
            DeviceTypeKind: kind,
            VendorId: vendorId,
            ProductId: productId,
            SerialNumber: serial,
            IsMfiCertified: isMfi,
            ConnectionInterface: "USB",
            DriveLetter: null,
            Capabilities: capabilities);
    }

    private static UsbDeviceTypeKind ClassifyDevice(ushort vendorId, string name)
    {
        var lowered = name.ToLowerInvariant();

        if (vendorId == AppleVendorId)
        {
            if (lowered.Contains("iphone") || lowered.Contains("ipad") || lowered.Contains("ipod") ||
                lowered.Contains("airpods") || lowered.Contains("earpods") || lowered.Contains("beats"))
            {
                return UsbDeviceTypeKind.AppleMfi;
            }

            return UsbDeviceTypeKind.AppleMfi;
        }

        if (AndroidVendorIds.Contains(vendorId) ||
            lowered.Contains("android") || lowered.Contains("pixel") || lowered.Contains("galaxy"))
        {
            return UsbDeviceTypeKind.Android;
        }

        if (StorageVendorIds.Contains(vendorId) ||
            lowered.Contains("flash") || lowered.Contains("usb drive") || lowered.Contains("thumb"))
        {
            return UsbDeviceTypeKind.FlashDrive;
        }

        if (lowered.Contains("disk") || lowered.Contains("ssd") || lowered.Contains("hdd") ||
            lowered.Contains("drive") || lowered.Contains("storage"))
        {
            return UsbDeviceTypeKind.ExternalDrive;
        }

        if (lowered.Contains("audio") || lowered.Contains("headphone") || lowered.Contains("headset") ||
            lowered.Contains("microphone") || lowered.Contains("speaker"))
        {
            return UsbDeviceTypeKind.Audio;
        }

        return UsbDeviceTypeKind.Unknown;
    }

    private static List<EnumeratedUsbDevice> MergeDevices(
        List<EnumeratedUsbDevice> usbDevices,
        List<RemovableVolume> storageVolumes)
    {
        var merged = new List<EnumeratedUsbDevice>(usbDevices);

        foreach (var volume in storageVolumes)
        {
            // Attach the storage facts to an existing storage-class USB device when we can,
            // otherwise surface the volume as its own storage row so removable media that
            // the UsbDevice selector does not expose is still represented.
            var host = merged.FirstOrDefault(d =>
                d.DeviceTypeKind is UsbDeviceTypeKind.ExternalDrive or UsbDeviceTypeKind.FlashDrive &&
                string.IsNullOrEmpty(d.DriveLetter));

            if (host is not null)
            {
                merged.Remove(host);
                merged.Add(host with
                {
                    DriveLetter = volume.DriveLetter,
                    ConnectionInterface = "USB mass storage",
                    Capabilities = host.Capabilities.Concat(volume.Capabilities).ToList()
                });
            }
            else
            {
                merged.Add(new EnumeratedUsbDevice(
                    DeviceId: volume.DriveLetter,
                    Name: volume.Name,
                    DeviceTypeKind: UsbDeviceTypeKind.ExternalDrive,
                    VendorId: 0,
                    ProductId: 0,
                    SerialNumber: string.Empty,
                    IsMfiCertified: false,
                    ConnectionInterface: "USB mass storage",
                    DriveLetter: volume.DriveLetter,
                    Capabilities: volume.Capabilities));
            }
        }

        return merged
            .OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<RemovableVolume> EnumerateRemovableVolumes()
    {
        try
        {
            return DriveInfo.GetDrives()
                .Where(drive => drive.IsReady && drive.DriveType == DriveType.Removable)
                .OrderBy(drive => drive.Name, StringComparer.OrdinalIgnoreCase)
                .Select(drive => new RemovableVolume(
                    DriveLetter: drive.Name,
                    Name: string.IsNullOrWhiteSpace(drive.VolumeLabel)
                        ? $"Removable drive {drive.Name}"
                        : drive.VolumeLabel,
                    Capabilities: new List<string>
                    {
                        drive.DriveFormat,
                        $"{FormatBytes(drive.TotalSize)} total",
                        $"{FormatBytes(drive.AvailableFreeSpace)} free"
                    }))
                .ToList();
        }
        catch (Exception error) { throw new IOException("USB storage enumeration failed.", error); }
    }

    private static string ReadStringProperty(DeviceInformation info, string key)
    {
        if (info.Properties.TryGetValue(key, out var value) && value is string text)
        {
            return text;
        }

        return string.Empty;
    }

    private static string ExtractSerial(string? instanceId)
    {
        if (string.IsNullOrWhiteSpace(instanceId))
        {
            return string.Empty;
        }

        // Instance id is "USB\VID_xxxx&PID_yyyy\<serial-or-instance>".
        var lastSeparator = instanceId.LastIndexOf('\\');
        if (lastSeparator < 0 || lastSeparator == instanceId.Length - 1)
        {
            return string.Empty;
        }

        var tail = instanceId[(lastSeparator + 1)..];

        // A tail that contains '&' is an OS-generated instance path (not a real serial).
        if (tail.Contains('&'))
        {
            return string.Empty;
        }

        return tail;
    }

    private static ushort ParseHex(string value) =>
        ushort.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : (ushort)0;

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        var units = new[] { "KB", "MB", "GB", "TB" };
        var value = bytes / 1024d;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return $"{value:0.0} {units[unitIndex]}";
    }

    private sealed record EnumeratedUsbDevice(
        string DeviceId,
        string Name,
        UsbDeviceTypeKind DeviceTypeKind,
        ushort VendorId,
        ushort ProductId,
        string SerialNumber,
        bool IsMfiCertified,
        string ConnectionInterface,
        string? DriveLetter,
        IReadOnlyList<string> Capabilities)
    {
        public UsbDeviceItem ToItem() => new(
            Name,
            DeviceId,
            DeviceTypeKind.ToDisplayString(),
            VendorId != 0 || ProductId != 0
                ? string.Create(CultureInfo.InvariantCulture, $"0x{VendorId:X4}")
                : string.Empty,
            VendorId != 0 || ProductId != 0
                ? string.Create(CultureInfo.InvariantCulture, $"0x{ProductId:X4}")
                : string.Empty,
            SerialNumber ?? string.Empty,
            ConnectionInterface,
            // A15 — pass the capability strings through as a list (no string.Join); the
            // view projects them to chips. A copied list keeps the record value-immutable.
            Capabilities.Count == 0
                ? System.Array.Empty<string>()
                : Capabilities.ToList(),
            DeviceTypeKind.ToKey(),
            IsMfiCertified);
    }

    private sealed record RemovableVolume(
        string DriveLetter,
        string Name,
        IReadOnlyList<string> Capabilities);
}

/// <summary>Coarse device classification mirroring the Mac <c>USBCDeviceType</c>.</summary>
public enum UsbDeviceTypeKind
{
    AppleMfi,
    Android,
    ExternalDrive,
    FlashDrive,
    Audio,
    Unknown
}

internal static class UsbDeviceTypeKindExtensions
{
    public static string ToDisplayString(this UsbDeviceTypeKind kind) => kind switch
    {
        UsbDeviceTypeKind.AppleMfi => "Apple device",
        UsbDeviceTypeKind.Android => "Android device",
        UsbDeviceTypeKind.ExternalDrive => "External drive",
        UsbDeviceTypeKind.FlashDrive => "USB flash drive",
        UsbDeviceTypeKind.Audio => "Audio device",
        _ => "USB device"
    };

    // Stable key consumed by the icon/brush converters (not user-facing).
    public static string ToKey(this UsbDeviceTypeKind kind) => kind switch
    {
        UsbDeviceTypeKind.AppleMfi => "appleMfi",
        UsbDeviceTypeKind.Android => "android",
        UsbDeviceTypeKind.ExternalDrive => "externalDrive",
        UsbDeviceTypeKind.FlashDrive => "flashDrive",
        UsbDeviceTypeKind.Audio => "audio",
        _ => "unknown"
    };
}

public sealed record UsbManagementWorkspaceSnapshot(
    DateTimeOffset CapturedAt,
    IReadOnlyList<UsbDeviceStat> Stats,
    IReadOnlyList<UsbDeviceItem> Devices,
    string? SkybridgeFailureStatus = null);

public sealed record UsbDeviceStat(
    string Title,
    string Value,
    string Detail);

public sealed record UsbDeviceItem(
    string Name,
    string DeviceId,
    string DeviceType,
    string VendorId,
    string ProductId,
    string SerialNumber,
    string ConnectionInterface,
    // A15 — the REAL per-device capability strings (e.g. "USB", "Connected", a drive
    // format, "<n> GB total/free"), kept as a list so the Mac LazyVGrid chip parity can
    // render each as its own chip instead of one joined "a; b; c" line. The values come
    // straight from the enumeration pass and stay non-localized (device formats / "USB" /
    // "Connected"). An empty list renders no chip row (honest — no fabricated capability).
    IReadOnlyList<string> Capabilities,
    string DeviceTypeKey,
    bool IsMfiCertified,
    string? SkybridgeStatus = null,
    string? SkybridgeUdid = null,
    string? SkybridgeFingerprint = null,
    string? SkybridgeDeviceId = null);
