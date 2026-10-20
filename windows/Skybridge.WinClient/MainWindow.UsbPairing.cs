using Microsoft.UI.Xaml;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.RemoteControl;
using Skybridge.WinClient.ViewModels;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private Task? _usbDeviceOperation;
    private CancellationTokenSource? _usbDeviceCancellation;
    private AccountAudioAuthorization? _usbDeviceEpoch;
    private Exception? _usbDeviceReleaseFailure;
    private bool _usbDeviceRequiresOnline;

    private async void OnUsbPairClicked(object sender, RoutedEventArgs args) =>
        await RunUsbDeviceFromUiAsync(sender, pairing: true);

    private async void OnUsbConnectClicked(object sender, RoutedEventArgs args) =>
        await RunUsbDeviceFromUiAsync(sender, pairing: false);

    private async Task RunUsbDeviceFromUiAsync(object sender, bool pairing)
    {
        if (_hostShutdownInProgress || _usbDeviceOperation is { IsCompleted: false } ||
            _usbDeviceReleaseFailure is not null) return;
        if (sender is not FrameworkElement { DataContext: UsbDeviceItemView item } ||
            item.SkybridgeUdid is not { } udid || item.SkybridgeFingerprint is not { } fingerprint ||
            item.SkybridgeDeviceId is not { } deviceId ||
            !(pairing ? item.CanPairSkybridge : item.CanConnectSkybridge)) return;
        if (pairing ? !ViewModel.AccountSession.IsSignedIn : ViewModel.AccountSession.ReadAudioReceiverAccount() is null)
        {
            ViewModel.ReportUsbManagementStatus(RemoteControlText(pairing ? "UsbPairSignIn" : "UsbConnectSignIn"));
            ViewModel.ToggleAccountOverlay();
            return;
        }
        var cancellation = new CancellationTokenSource();
        _usbDeviceCancellation = cancellation;
        _usbDeviceRequiresOnline = pairing;
        UsbDevicesInteraction.IsEnabled = false;
        _usbDeviceOperation = pairing ? PairUsbFromWindowAsync(udid, fingerprint, deviceId, cancellation.Token)
            : ConnectUsbFromWindowAsync(udid, fingerprint, deviceId, cancellation.Token);
        try { await _usbDeviceOperation; }
        finally
        {
            _usbDeviceEpoch = null;
            // Failed release retains its owner and keeps new work disabled.
            if (_usbDeviceReleaseFailure is null)
            {
                _usbDeviceCancellation = null;
                cancellation.Dispose();
                UsbDevicesInteraction.IsEnabled = true;
            }
            ViewModel.UpdateUsbConnections(_remoteControlWorkspace.ReadConnectedUsbPeers());
        }
    }

    private async Task PairUsbFromWindowAsync(string udid, string fingerprint, string deviceId, CancellationToken token)
    {
        bool committed = false;
        try
        {
            var account = ViewModel.AccountSession;
            var epoch = account.RequireAudioAuthorization();
            _usbDeviceEpoch = epoch;
            var authentication = await account.GetDeviceAuthenticationAsync(token)
                ?? throw new InvalidOperationException("The signed-in account is unavailable.");
            token.ThrowIfCancellationRequested();
            var target = _usbWorkspace.RequireEnrollmentTarget(udid, fingerprint, deviceId);
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbPairPending"));
            await _remoteControlWorkspace.PairUsbPeerAsync(target, authentication, epoch,
                new NativePairingApproval(this), token);
            committed = true;
            // Read the saved identity back through the ordinary workspace provider.
            // A failed refresh cannot undo or disguise the durable trust commit.
            await ViewModel.RefreshUsbAfterPairingAsync();
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbPairSaved"));
        }
        catch (Exception error)
        {
            RetainUsbReleaseFailure(error);
            WindowsRuntimeLog.Write(error is OperationCanceledException or LanPibRejectedException
                ? WindowsLogLevel.Info : WindowsLogLevel.Error, "UsbPairing", error.GetType().Name);
            if (_hostShutdownInProgress) return;
            string key = committed ? "UsbPairSavedRefreshFailed" :
                _usbDeviceReleaseFailure is not null
                ? "UsbPairCleanupFailed" : error switch
            {
                OperationCanceledException => "UsbPairCanceled",
                LanPibRejectedException { Code: "localApprovalRejected" or "remote_userRejected" } => "UsbPairDeclined",
                TimeoutException => "UsbPairTimedOut",
                _ => "UsbPairFailed"
            };
            ViewModel.ReportUsbManagementStatus(RemoteControlText(key));
        }
    }

    private async Task ConnectUsbFromWindowAsync(string udid, string fingerprint, string deviceId, CancellationToken token)
    {
        try
        {
            var account = ViewModel.AccountSession;
            var receiver = account.ReadAudioReceiverAccount()
                ?? throw new InvalidOperationException("USB audio requires current account authority.");
            var epoch = receiver.Authorization; _usbDeviceEpoch = epoch;
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbConnectPending"));
            // A prior finite offline grant does not manufacture ordinary bearer authentication.
            var authentication = epoch.IsOffline ? null : await account.GetAudioAuthenticationAsync(epoch, token);
            token.ThrowIfCancellationRequested(); epoch.RequireCurrent();
            var target = _usbWorkspace.RequireConnectionTarget(udid, fingerprint, deviceId);
            await _remoteControlWorkspace.ConnectUsbControlAsync(target, authentication, epoch,
                new RemoteControlViewerAccount(receiver.DisplayName, receiver.NebulaId), token);
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbConnectReady"));
        }
        catch (Exception error)
        {
            RetainUsbReleaseFailure(error);
            WindowsRuntimeLog.Write(error is OperationCanceledException ? WindowsLogLevel.Info : WindowsLogLevel.Error,
                "UsbConnection", error.GetType().Name);
            if (_hostShutdownInProgress) return;
            ViewModel.ReportUsbManagementStatus(RemoteControlText(_usbDeviceReleaseFailure is not null ? "UsbDeviceCleanupFailed" :
                error is OperationCanceledException ? "UsbConnectCanceled" : "UsbConnectFailed"));
        }
    }

    private void RetainUsbReleaseFailure(Exception error)
    {
        if (ProductBootstrapReleaseException.ContainsUnreleasedOwner(error))
            _usbDeviceReleaseFailure = error;
    }

    private void ObserveUsbDeviceAuthorization()
    {
        if (_usbDeviceEpoch is { } epoch && (!epoch.IsCurrent || _usbDeviceRequiresOnline && epoch.IsOffline))
            CancelUsbDeviceOperation();
    }

    private void CancelUsbDeviceOperation()
    {
        if (_usbDeviceCancellation is not { } owner || owner.IsCancellationRequested) return;
        try { owner.Cancel(); }
        catch (Exception error)
        {
            _usbDeviceReleaseFailure = error;
            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "UsbDeviceCancellation", error.GetType().Name);
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbDeviceCleanupFailed"));
        }
    }

    private async Task StopUsbDeviceOperationAsync()
    {
        CancelUsbDeviceOperation();
        try
        {
            if (_usbDeviceOperation is { } operation)
                await operation.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception failure) when (_usbDeviceReleaseFailure is { })
        { throw new AggregateException(_usbDeviceReleaseFailure, failure); }
        if (_usbDeviceReleaseFailure is { } failureToRelease)
            throw new InvalidOperationException("USB device operation did not release cleanly.", failureToRelease);
    }
}
