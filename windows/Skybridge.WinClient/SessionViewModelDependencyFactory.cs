using Skybridge.WinClient.ViewModels;
using Skybridge.WinClient.Services;

namespace Skybridge.WinClient;

internal static class SessionViewModelDependencyFactory
{
    public static SessionViewModelDependencies CreateConfigured(
        IFileTransferWorkspaceClient fileTransferClient,
        ITopBarNotificationCenterClient notifications,
        SettingsService settings,
        System.Action openThemePicker, System.Func<CrossNetworkConnectionRequest, System.Threading.Tasks.Task<CrossNetworkConnectionSnapshot>>? liveCodeAction = null) =>
        CreateConfigured(fileTransferClient,
            new TopBarStatusClient(notifications, new SettingsThemePreferenceClient(settings), openThemePicker), settings,
            liveCodeAction is null ? null : new CrossNetworkConnectionClient(liveCodeAction));

    public static SessionViewModelDependencies CreateConfigured(IFileTransferWorkspaceClient? fileTransferClient = null, ITopBarStatusClient? topBarStatusClient = null, SettingsService? settingsService = null, ICrossNetworkConnectionClient? connectionCodes = null) =>
        WindowsNativeRuntimeDependencyFactory.CreateFromEnvironment(fileTransferClient, topBarStatusClient, settingsService, connectionCodes);

    public static SessionViewModelDependencies CreateDefault() =>
        WindowsNativeRuntimeDependencyFactory.CreateFromEnvironment();
}
