using System.Net.Http;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.ViewModels;
namespace Skybridge.WinClient;
public sealed partial class MainWindow
{
    private AccountDevicesCoordinator? _accountDevices;
    private HttpClient? _accountDeviceHttp;
    private AudioAccountMembershipProvider? _audioMembership;
    private AudioAccountCredentialDispatcher? _audioCredentials;
    private AccountDevicesEntry? _accountDevicesReturnFocus;
    private void ConfigureAccountDevices()
    {
        _accountDeviceHttp=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(8)};
        var account=ViewModel.AccountSession;
        _audioCredentials=new AudioAccountCredentialDispatcher(action => DispatcherQueue.TryEnqueue(() => action()),account.GetAudioAuthenticationAsync);
        _audioMembership=new AudioAccountMembershipProvider(_accountDeviceHttp,account.ReadAudioAuthorization,_audioCredentials.AuthenticateAsync);
        _accountDevices=new AccountDevicesCoordinator(new AccountDeviceRosterClient(_accountDeviceHttp,new AudioAccountRegistryObserver(_audioMembership)),account.GetDeviceAuthenticationAsync,
            _remoteControlWorkspace.AccountIdentityAsync,WindowsAccountDeviceMetadata.ReadAsync,RemoteControlText);
        AccountDevicesFooter.Configure(_accountDevices,"AccountDevices.OpenFooter");
        AccountDevicesDashboard.Configure(_accountDevices,"AccountDevices.OpenDashboard",glassSurface: true);
        AccountDevicesSettings.Configure(_accountDevices,"AccountDevices.OpenSettings");
        AccountDevicesOverlay.Configure(_accountDevices);
        AccountDevicesDiscovery.Configure(_accountDevices, embedded: true);
        AccountDevicesFooter.OpenRequested+=OnOpenAccountDevices;
        AccountDevicesDashboard.OpenRequested+=OnOpenAccountDevices;
        AccountDevicesSettings.OpenRequested+=OnOpenAccountDevices;
        AccountDevicesOverlay.CloseRequested+=OnCloseAccountDevices;
        account.IdentityChanged+=OnAccountDevicesIdentityChanged;
        _accountDevices.SetAccount(account.AccountDeviceScope);
        _accountDevices.Start();
    }
    private void OnAccountDevicesIdentityChanged(object? sender,AccountIdentity account) => _accountDevices?.SetAccount(ViewModel.AccountSession.AccountDeviceScope);
    private void OnOpenAccountDevices(object? sender,EventArgs args)
    {
        _accountDevicesReturnFocus=sender as AccountDevicesEntry;
        AccountDevicesOverlay.Visibility=Visibility.Visible;
        // Keep keyboard traversal inside the modal and restore its invoking control.
        SidebarNavigation.IsEnabled=false;
        DispatcherQueue.TryEnqueue(() => { if(AccountDevicesOverlay.Visibility==Visibility.Visible) AccountDevicesOverlay.FocusClose(); });
        _accountDevices?.Refresh();
    }
    private void OnCloseAccountDevices(object? sender,EventArgs args)
    {
        AccountDevicesOverlay.Visibility=Visibility.Collapsed;
        SidebarNavigation.IsEnabled=true;
        _accountDevicesReturnFocus?.RestoreFocus();
    }
    private async Task StopAccountDevicesAsync()
    {
        ViewModel.AccountSession.IdentityChanged-=OnAccountDevicesIdentityChanged;
        AccountDevicesFooter.OpenRequested-=OnOpenAccountDevices;
        AccountDevicesDashboard.OpenRequested-=OnOpenAccountDevices;
        AccountDevicesSettings.OpenRequested-=OnOpenAccountDevices;
        AccountDevicesOverlay.CloseRequested-=OnCloseAccountDevices;
        // Revoke audio immediately and drain the existing device loop and UI credential callback
        // before releasing the shared HTTP transport. Hiding the overlay does not stop these owners.
        await Task.WhenAll(_accountDevices?.DisposeAsync().AsTask() ?? Task.CompletedTask,
            _audioMembership?.DisposeAsync().AsTask() ?? Task.CompletedTask,
            _audioCredentials?.DisposeAsync().AsTask() ?? Task.CompletedTask);
        _accountDeviceHttp?.Dispose();
    }
}
