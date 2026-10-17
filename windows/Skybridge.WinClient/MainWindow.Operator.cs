using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private AppOperatorServer? _operatorServer;
    private readonly SettingsService _operatorSettings;
    private static readonly string[] OperatorMethods = ["app.status", "app.settings", "app.settings.set",
        "app.remote_desktop.interfaces", "app.remote_desktop.start", "app.remote_desktop.stop"];

    private Task<JsonObject> DispatchOperatorAsync(AppOperatorRequest request, CancellationToken token)
        => AppOperatorServer.DispatchAsync(action => DispatcherQueue.TryEnqueue(() => action()), async cancellation =>
        {
            cancellation.ThrowIfCancellationRequested();
            if (_hostShutdownInProgress || _hostShutdownComplete)
                throw new AppOperatorException("app_closing", "The application is closing.");
            return await HandleOperatorAsync(request, cancellation);
        }, token);

    private JsonObject OperatorHostSnapshot()
    {
        var snapshot = _remoteControlWorkspace.ReadOperatorHost();
        return new() { ["generation"] = snapshot.Generation, ["enabled"] = snapshot.Enabled,
            ["state"] = snapshot.Status?.State.ToString().ToLowerInvariant() ?? "stopped",
            ["session_count"] = snapshot.Status?.Sessions?.Count ?? 0,
            ["frames_sent"] = snapshot.Status?.FramesSent ?? 0 };
    }

    private string ObservedAppearance() => RootShell.RequestedTheme switch
    {
        ElementTheme.Default => "system", ElementTheme.Light => "light", ElementTheme.Dark => "dark",
        _ => throw new AppOperatorException("setting_effect_unconfirmed", "The window theme could not be read.")
    };

    private JsonObject OperatorSettingsSnapshot(bool requirePersistence)
    {
        string value = ViewModel.Settings.AppearanceMode;
        string observed = ObservedAppearance();
        if (value != observed)
            throw new AppOperatorException("setting_effect_unconfirmed", "The setting and visible window theme disagree.");
        string? persisted = null;
        if (requirePersistence)
        {
            try { persisted = _operatorSettings.ReadPersistedAppearanceMode(); }
            catch (IOException) { throw new AppOperatorException("setting_persistence_unconfirmed", "The saved setting could not be read."); }
            if (persisted != value)
                throw new AppOperatorException("setting_persistence_unconfirmed", "The saved setting differs from the current window.");
        }
        return new() { ["settings"] = new JsonObject { ["appearance.mode"] = new JsonObject {
            ["value"] = value, ["observed_value"] = observed } },
            ["persistence"] = requirePersistence ? "persisted" : "not_checked" };
    }

    private static string InterfaceRef(RemoteControlNetworkInterface network)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            network.AdapterId + "\n" + network.Address + "\n" + network.InterfaceIndex))).ToLowerInvariant()[..24];

    private async Task<JsonObject> HandleOperatorAsync(AppOperatorRequest request, CancellationToken token)
    {
        var parameters = request.Parameters;
        switch (request.Method)
        {
            case "app.status":
                AppOperatorServer.RequireProperties(parameters);
                return new() { ["app_pid"] = Environment.ProcessId, ["runtime_id"] = "windows_app_runtime",
                    ["host"] = OperatorHostSnapshot(), ["settings"] = OperatorSettingsSnapshot(false)["settings"]!.DeepClone(),
                    ["capabilities"] = new JsonArray(OperatorMethods.Select(method => (JsonNode?)JsonValue.Create(method)).ToArray()) };
            case "app.settings":
                AppOperatorServer.RequireProperties(parameters);
                return OperatorSettingsSnapshot(true);
            case "app.settings.set":
                AppOperatorServer.RequireProperties(parameters, "id", "value");
                if (parameters.GetProperty("id").GetString() != "appearance.mode")
                    throw new AppOperatorException("setting_not_supported", "This setting has no confirmed local runtime handler.");
                if (parameters.GetProperty("value").ValueKind != JsonValueKind.String
                    || parameters.GetProperty("value").GetString() is not ("system" or "light" or "dark"))
                    throw new AppOperatorException("setting_value_invalid", "Appearance mode must be system, light or dark.");
                var requested = parameters.GetProperty("value").GetString()!;
                if (!_operatorSettings.RuntimeTruth.Trusted)
                    throw new AppOperatorException("setting_state_untrusted", "Resolve the stored-settings error in the app before changing its settings.");
                ViewModel.Settings.AppearanceMode = requested;
                string durable;
                try { durable = _operatorSettings.PersistAndReadBackAppearanceMode(); }
                catch (IOException) { throw new AppOperatorException("setting_persistence_unconfirmed", "The theme changed but its saved value was not confirmed. Inspect settings before retrying."); }
                if (durable != requested || ObservedAppearance() != requested)
                    throw new AppOperatorException("setting_effect_unconfirmed", "The saved setting or window theme did not confirm the requested value.");
                return new() { ["setting_id"] = "appearance.mode", ["requested_value"] = requested,
                    ["observed_value"] = ObservedAppearance(), ["persisted"] = true, ["effect"] = "live_app_theme" };
            case "app.remote_desktop.interfaces":
                AppOperatorServer.RequireProperties(parameters);
                var interfaces = await WindowsDeviceWorkspace.OperatorNetworkInterfacesAsync(token);
                return new() { ["interfaces"] = new JsonArray(interfaces.Select(network => (JsonNode?)new JsonObject {
                    ["interface_ref"] = InterfaceRef(network), ["name"] = network.Name }).ToArray()) };
            case "app.remote_desktop.start":
                AppOperatorServer.RequireProperties(parameters, "interface_ref");
                var selectedRef = parameters.GetProperty("interface_ref").GetString();
                var available = await WindowsDeviceWorkspace.OperatorNetworkInterfacesAsync(token);
                var selected = available.SingleOrDefault(network => InterfaceRef(network) == selectedRef)
                    ?? throw new AppOperatorException("interface_unavailable", "Choose an interface from the current app interface list.");
                // Reuse the existing identity/approval owner; this does not import or approve peers.
                var preparation = await _remoteControlWorkspace.PrepareAsync(token);
                if (preparation.TrustedDeviceNames.Count == 0)
                    throw new AppOperatorException("trusted_controller_required", "Use the app to pair a trusted controller before enabling the host.");
                token.ThrowIfCancellationRequested();
                try
                {
                    // Preparation remains cancellable until the workspace commits the host.
                    await _remoteControlWorkspace.StartAsync(selected, token);
                    var started = OperatorHostSnapshot();
                    if (started["enabled"]?.GetValue<bool>() != true || started["state"]?.GetValue<string>() == "failed")
                        throw new AppOperatorException("host_start_unconfirmed", "The host did not confirm listening readiness.");
                    return started;
                }
                catch (InvalidOperationException) { throw new AppOperatorException("host_start_failed", "The app could not enable this host. Inspect the remote-control panel."); }
                finally { RemoteControlHost.SynchronizeOperatorRuntime(); }
            case "app.remote_desktop.stop":
                AppOperatorServer.RequireProperties(parameters, "generation");
                if (!parameters.GetProperty("generation").TryGetInt64(out var generation) || generation < 0)
                    throw new AppOperatorException("invalid_parameters", "Use the host generation from app status.");
                try
                {
                    await _remoteControlWorkspace.StopOperatorHostAsync(generation, token);
                    var stopped = OperatorHostSnapshot();
                    if (stopped["enabled"]?.GetValue<bool>() != false)
                        throw new AppOperatorException("host_stop_unconfirmed", "The host still owns runtime resources.");
                    return stopped;
                }
                catch (RemoteControlHostGenerationMismatchException)
                {
                    throw new AppOperatorException("host_generation_changed", "Read app status again before stopping this host.");
                }
                finally { RemoteControlHost.SynchronizeOperatorRuntime(); }
            default:
                throw new AppOperatorException("method_not_supported", "This app does not implement that operator method.");
        }
    }
}
