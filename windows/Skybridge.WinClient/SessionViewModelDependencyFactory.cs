using Skybridge.WinClient.ViewModels;
using Skybridge.WinClient.Services;

namespace Skybridge.WinClient;

internal static class SessionViewModelDependencyFactory
{
    public static SessionViewModelDependencies CreateConfigured(
        IFileTransferWorkspaceClient fileTransferClient,
        ITopBarNotificationCenterClient notifications,
        SettingsService settings,
        System.Action openThemePicker, ICrossNetworkConnectionClient? connectionCodes = null) =>
        CreateConfigured(fileTransferClient,
            new TopBarStatusClient(notifications, new SettingsThemePreferenceClient(settings), openThemePicker), settings, connectionCodes);

    public static SessionViewModelDependencies CreateConfigured(IFileTransferWorkspaceClient? fileTransferClient = null, ITopBarStatusClient? topBarStatusClient = null, SettingsService? settingsService = null, ICrossNetworkConnectionClient? connectionCodes = null) =>
        WindowsNativeRuntimeDependencyFactory.CreateFromEnvironment(fileTransferClient, topBarStatusClient, settingsService, connectionCodes);

    public static SessionViewModelDependencies CreateDefault() =>
        WindowsNativeRuntimeDependencyFactory.CreateFromEnvironment();
}
