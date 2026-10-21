using System;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.UI.Xaml.Data;

namespace Skybridge.WinClient.Converters;

/// <summary>
/// Localizes the per-page status line (the "Ready" text on each workspace page) at the
/// BINDING layer only  -- without ever touching the backing string the providers emit.
///
/// WHY a binding-layer converter and NOT a localized backing field:
///   The 7 workspace providers set their initial status to the canonical English literal
///   <c>"Ready"</c> (e.g. <c>_discoveryStatus = "Ready"</c>, <c>DefaultInitialStatus = "Ready"</c>),
///   and two CI gates assert that exact literal  -- Scripts/verify-windows-startup-state.ps1
///   (e.g. <c>AssertEqual("Ready", state.DiscoveryStatus, ...)</c>) and
///   Scripts/verify-windows-ui-parity.ps1 (the source-literal block
///   <c>_discoveryStatus = "Ready"</c> ... <c>_settingsStatus = "Ready"</c>). Changing the
///   field/value would break both gates. So the canonical English string stays the source of
///   truth and we translate ONLY what the user sees.
///
/// Behaviour:
///   - A KNOWN canonical English status (Ready / Idle / Preview ready / Intent ready /
///     No Core-validated peers / Discovery stopped) is mapped to its localized form for the
///     current UI language.
///   - Any UNKNOWN / dynamic string (honest live messages such as
///     "Prepared 192.168.0.10:11550", "Scanning 12:03:44 UTC", "Validated 3 peer(s)") passes
///     through VERBATIM  -- we never swallow a real status message into a generic localized one.
///   - null / empty passes through unchanged.
///
/// Language resolution mirrors App.xaml.cs's source of truth:
///   1. Microsoft.Windows.Globalization.ApplicationLanguages.PrimaryLanguageOverride (the
///      explicit choice the app applies on launch), when non-empty.
///   2. otherwise the current UI culture (system display language).
/// The resolved tag is folded to one of: "zh" (zh-Hans*), "ja", or "en" (default).
///
/// Value resolution is resw-FIRST, dictionary-FALLBACK (reliability over elegance):
///   We first try the indexed resources.pri via
///   Microsoft.Windows.ApplicationModel.Resources.ResourceManager (the WinAppSDK MRT Core
///   manager that works unpackaged  -- the same resource system x:Uid uses), reading the
///   Status.* key under a ResourceContext pinned to the resolved language. If that lookup
///   throws or returns nothing (e.g. an unpackaged path quirk), we fall back to a small
///   in-code trilingual table so a value is ALWAYS produced. The resw values and the table
///   are kept identical, so either path renders the same text.
/// </summary>
public sealed class StatusKeyToLocalizedConverter : IValueConverter
{
    // Canonical English status string -> Status.* resw key (also the in-code table key below).
    private static readonly Dictionary<string, string> CanonicalToResourceKey =
        new(StringComparer.Ordinal)
        {
            ["SkyBridge paired; not connected"] = "Status.UsbPaired",
            ["SkyBridge securely connected"] = "Status.UsbConnected",
            ["SkyBridge connection ended"] = "Status.UsbConnectionEnded",
            ["SkyBridge found; pairing required"] = "Status.UsbUnpaired",
            ["SkyBridge identity differs from saved pairing"] = "Status.UsbIdentityConflict",
            ["SkyBridge found; saved pairing could not be read"] = "Status.UsbPairingUnavailable",
            ["Open SkyBridge on the connected Apple device"] = "Status.UsbOpenApp",
            ["USB device is no longer available"] = "Status.UsbDeviceUnavailable",
            ["SkyBridge identity verification failed"] = "Status.UsbIdentityInvalid",
            ["SkyBridge USB signature support is unavailable"] = "Status.UsbSignatureUnsupported",
            ["SkyBridge USB device did not respond in time"] = "Status.UsbTimeout",
            ["SkyBridge USB inspection failed"] = "Status.UsbInspectionFailed",
            ["Apple USB connection service is unavailable"] = "Status.UsbServiceUnavailable",
            ["Connect at most eight Apple USB devices to inspect SkyBridge"] = "Status.UsbDeviceLimit",
            ["SkyBridge found; pairing status is not loaded"] = "Status.UsbPairingNotLoaded",
            ["Multiple USB devices share one SkyBridge identity"] = "Status.UsbDuplicateIdentity",
            ["Ready"] = "Status.Ready",
            ["Idle"] = "Status.Idle",
            ["Preview ready"] = "Status.PreviewReady",
            ["Intent ready"] = "Status.IntentReady",
            ["No Core-validated peers"] = "Status.NoCoreValidatedPeers",
            ["Discovery stopped"] = "Status.DiscoveryStopped",
            // Settings Actions row State (SettingsActionItem.State; visible "Settings Actions"
            // list). "Ready"/"Preview ready"/"Intent ready" already map above; add the gated
            // "Disabled" state shown for Open System Preferences / Clear History Data. The
            // canonical English State stays the model value; only the displayed text localizes.
            ["Disabled"] = "Status.Disabled",
            // Top-bar CONNECTION pill (TopBarConnectionStatus = EngineConnectionState.ToString(),
            // see IEngineClient.EngineConnectionState). The enum name stays the canonical backing
            // value the gate + state machine key off (verify-windows-startup-state asserts
            // EngineConnectionState.Disconnected; native-runtime-profile feeds "Disconnected"
            // through BuildStatusUpdate). Only the displayed pill text localizes here.
            ["Disconnected"] = "Status.Disconnected",
            ["Connecting"] = "Status.Connecting",
            ["Connected"] = "Status.Connected",
            ["Reconnecting"] = "Status.Reconnecting",
            ["ShuttingDown"] = "Status.ShuttingDown",
            // Top-bar DIAGNOSTICS / FPS pill (TopBarDiagnosticsStatus = PerformanceStatus, the
            // honest coarse health scalar from DashboardMetricsClient: "Nominal"/"Busy"). The
            // English scalar stays the backing value the top bar + gate key off; only the
            // displayed pill text localizes.
            ["Nominal"] = "Status.Nominal",
            ["Busy"] = "Status.Busy",
            // Page status line (StatusMessage). The session/engine status machine emits these
            // canonical completed messages; dynamic / ellipsis ("Connecting...") variants are NOT
            // mapped and pass through verbatim so live messages survive. "Idle" already maps above.
            ["Heartbeat acknowledged"] = "Status.HeartbeatAcknowledged",
        };

    // In-code trilingual fallback, keyed by resource key then language fold ("en"/"zh"/"ja").
    // Mirrors Strings/{en-US,zh-Hans,ja}/Resources.resw Status.* values exactly.
    private static readonly Dictionary<string, Dictionary<string, string>> FallbackTable =
        new(StringComparer.Ordinal)
        {
            ["Status.UsbPaired"] = new() { ["en"] = "SkyBridge paired; not connected", ["zh"] = "SkyBridge 已配对，尚未连接", ["ja"] = "SkyBridge はペアリング済み・未接続" },
            ["Status.UsbConnected"] = new() { ["en"] = "SkyBridge securely connected", ["zh"] = "SkyBridge 已安全连接", ["ja"] = "SkyBridge に安全に接続済み" },
            ["Status.UsbConnectionEnded"] = new() { ["en"] = "SkyBridge connection ended", ["zh"] = "SkyBridge 连接已结束", ["ja"] = "SkyBridge 接続は終了しました" },
            ["Status.UsbUnpaired"] = new() { ["en"] = "SkyBridge found; pairing required", ["zh"] = "已发现 SkyBridge，需要配对", ["ja"] = "SkyBridge を検出しました。ペアリングが必要です" },
            ["Status.UsbIdentityConflict"] = new() { ["en"] = "SkyBridge identity differs from saved pairing", ["zh"] = "设备身份与已保存的配对记录不一致", ["ja"] = "デバイスの識別情報が保存済みのペアリングと一致しません" },
            ["Status.UsbPairingUnavailable"] = new() { ["en"] = "SkyBridge found; saved pairing could not be read", ["zh"] = "已识别 SkyBridge，但无法读取配对记录", ["ja"] = "SkyBridge を検出しましたが、保存済みのペアリングを読み取れません" },
            ["Status.UsbOpenApp"] = new() { ["en"] = "Open SkyBridge on the connected Apple device", ["zh"] = "请在已连接的 Apple 设备上打开 SkyBridge", ["ja"] = "接続した Apple デバイスで SkyBridge を開いてください" },
            ["Status.UsbDeviceUnavailable"] = new() { ["en"] = "USB device is no longer available", ["zh"] = "USB 设备已断开", ["ja"] = "USB デバイスが切断されました" },
            ["Status.UsbIdentityInvalid"] = new() { ["en"] = "SkyBridge identity verification failed", ["zh"] = "SkyBridge 设备身份校验失败", ["ja"] = "SkyBridge のデバイス識別情報を検証できませんでした" },
            ["Status.UsbSignatureUnsupported"] = new() { ["en"] = "SkyBridge USB signature support is unavailable", ["zh"] = "当前系统无法验证此设备的签名", ["ja"] = "現在のシステムではこのデバイスの署名を検証できません" },
            ["Status.UsbTimeout"] = new() { ["en"] = "SkyBridge USB device did not respond in time", ["zh"] = "SkyBridge USB 设备响应超时", ["ja"] = "SkyBridge USB デバイスの応答がタイムアウトしました" },
            ["Status.UsbInspectionFailed"] = new() { ["en"] = "SkyBridge USB inspection failed", ["zh"] = "无法识别 USB 上的 SkyBridge", ["ja"] = "USB 上の SkyBridge を識別できませんでした" },
            ["Status.UsbServiceUnavailable"] = new() { ["en"] = "Apple USB connection service is unavailable", ["zh"] = "Apple USB 连接服务不可用", ["ja"] = "Apple USB 接続サービスを利用できません" },
            ["Status.UsbDeviceLimit"] = new() { ["en"] = "Connect at most eight Apple USB devices to inspect SkyBridge", ["zh"] = "请最多连接八台 Apple USB 设备后重试", ["ja"] = "Apple USB デバイスを 8 台以下にして再試行してください" },
            ["Status.UsbPairingNotLoaded"] = new() { ["en"] = "SkyBridge found; pairing status is not loaded", ["zh"] = "已发现 SkyBridge，配对状态尚未读取", ["ja"] = "SkyBridge を検出しました。ペアリング状態は未読込です" },
            ["Status.UsbDuplicateIdentity"] = new() { ["en"] = "Multiple USB devices share one SkyBridge identity", ["zh"] = "多个 USB 设备使用了相同的 SkyBridge 身份", ["ja"] = "複数の USB デバイスが同じ SkyBridge 識別情報を使用しています" },

            ["Status.Ready"] = new() { ["en"] = "Ready", ["zh"] = "就绪", ["ja"] = "準備完了" },
            ["Status.Idle"] = new() { ["en"] = "Idle", ["zh"] = "空闲", ["ja"] = "アイドル" },
            ["Status.PreviewReady"] = new() { ["en"] = "Preview ready", ["zh"] = "预览就绪", ["ja"] = "プレビュー準備完了" },
            ["Status.IntentReady"] = new() { ["en"] = "Intent ready", ["zh"] = "操作就绪", ["ja"] = "操作準備完了" },
            ["Status.NoCoreValidatedPeers"] = new() { ["en"] = "No Core-validated peers", ["zh"] = "未发现经核心校验的设备", ["ja"] = "コア検証済みのピアがありません" },
            ["Status.DiscoveryStopped"] = new() { ["en"] = "Discovery stopped", ["zh"] = "已停止发现", ["ja"] = "検出を停止しました" },
            ["Status.Disabled"] = new() { ["en"] = "Disabled", ["zh"] = "已禁用", ["ja"] = "無効" },
            ["Status.Disconnected"] = new() { ["en"] = "Disconnected", ["zh"] = "未连接", ["ja"] = "未接続" },
            ["Status.Connecting"] = new() { ["en"] = "Connecting", ["zh"] = "连接中", ["ja"] = "接続中" },
            ["Status.Connected"] = new() { ["en"] = "Connected", ["zh"] = "已连接", ["ja"] = "接続済み" },
            ["Status.Reconnecting"] = new() { ["en"] = "Reconnecting", ["zh"] = "重新连接中", ["ja"] = "再接続中" },
            ["Status.ShuttingDown"] = new() { ["en"] = "Shutting down", ["zh"] = "正在关闭", ["ja"] = "シャットダウン中" },
            ["Status.Nominal"] = new() { ["en"] = "Nominal", ["zh"] = "正常", ["ja"] = "正常" },
            ["Status.Busy"] = new() { ["en"] = "Busy", ["zh"] = "繁忙", ["ja"] = "ビジー" },
            ["Status.HeartbeatAcknowledged"] = new() { ["en"] = "Heartbeat acknowledged", ["zh"] = "心跳已确认", ["ja"] = "ハートビート確認済み" },
        };

    // Lazily-created MRT Core manager (shared; cheap to reuse). null if construction fails
    // (e.g. resources.pri unreachable)  -- in that case we always use the in-code table.
    private static Microsoft.Windows.ApplicationModel.Resources.ResourceManager? _resourceManager;
    private static bool _resourceManagerTried;

    public object Convert(object value, Type targetType, object parameter, string language)
    {
        var input = value as string;
        if (string.IsNullOrEmpty(input))
        {
            return value ?? string.Empty;
        }

        // Unknown / dynamic status -> pass through untouched (honest live messages survive).
        if (!CanonicalToResourceKey.TryGetValue(input, out var resourceKey))
        {
            return input;
        }

        var lang = ResolveLanguageFold();

        // resw-first: try the indexed resources.pri under the resolved language.
        var fromResw = TryResolveFromResw(resourceKey, lang);
        if (!string.IsNullOrEmpty(fromResw))
        {
            return fromResw!;
        }

        // Dictionary fallback (always yields a value for a known key).
        if (FallbackTable.TryGetValue(resourceKey, out var perLang) &&
            (perLang.TryGetValue(lang, out var localized) || perLang.TryGetValue("en", out localized)))
        {
            return localized;
        }

        // Last resort: the canonical English the caller passed in.
        return input;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }

    // Fold the active UI language to one of "zh" / "ja" / "en".
    private static string ResolveLanguageFold()
    {
        string? tag = null;
        try
        {
            var over = Microsoft.Windows.Globalization.ApplicationLanguages.PrimaryLanguageOverride;
            if (!string.IsNullOrWhiteSpace(over))
            {
                tag = over;
            }
        }
        catch (Exception)
        {
            // Runtime not ready / unsupported  -- fall through to the culture below.
        }

        if (string.IsNullOrWhiteSpace(tag))
        {
            try
            {
                tag = CultureInfo.CurrentUICulture.Name;
            }
            catch (Exception)
            {
                tag = "en";
            }
        }

        tag = (tag ?? "en").Trim().ToLowerInvariant();
        if (tag.StartsWith("zh", StringComparison.Ordinal))
        {
            return "zh";
        }
        if (tag.StartsWith("ja", StringComparison.Ordinal))
        {
            return "ja";
        }
        return "en";
    }

    // Returns the Status.* resw value for the requested language fold, or null on any failure.
    private static string? TryResolveFromResw(string resourceKey, string langFold)
    {
        var manager = GetResourceManager();
        if (manager is null)
        {
            return null;
        }

        try
        {
            var context = manager.CreateResourceContext();
            // Pin the language so the lookup honors the app's chosen UI language rather than
            // only the system default. BCP-47 tags are fine here.
            var bcp47 = langFold switch
            {
                "zh" => "zh-Hans",
                "ja" => "ja",
                _ => "en-US",
            };
            context.QualifierValues["Language"] = bcp47;

            // resw keys live under the "Resources" subtree; "Status.Ready" maps to
            // Resources/Status.Ready in the indexed map.
            var candidate = manager.MainResourceMap.TryGetValue("Resources/" + resourceKey, context);
            var text = candidate?.ValueAsString;
            return string.IsNullOrEmpty(text) ? null : text;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static Microsoft.Windows.ApplicationModel.Resources.ResourceManager? GetResourceManager()
    {
        if (_resourceManagerTried)
        {
            return _resourceManager;
        }

        _resourceManagerTried = true;
        try
        {
            _resourceManager = new Microsoft.Windows.ApplicationModel.Resources.ResourceManager();
        }
        catch (Exception)
        {
            _resourceManager = null;
        }
        return _resourceManager;
    }
}
