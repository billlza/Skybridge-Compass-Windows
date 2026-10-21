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
    private enum UsbDeviceAction { Pair, Connect, Disconnect }

    private async void OnUsbPairClicked(object sender, RoutedEventArgs args) =>
        await RunUsbDeviceFromUiAsync(sender, UsbDeviceAction.Pair);

    private async void OnUsbConnectClicked(object sender, RoutedEventArgs args) =>
        await RunUsbDeviceFromUiAsync(sender, UsbDeviceAction.Connect);

    private async void OnUsbDisconnectClicked(object sender, RoutedEventArgs args) =>
        await RunUsbDeviceFromUiAsync(sender, UsbDeviceAction.Disconnect);

    private async Task RunUsbDeviceFromUiAsync(object sender, UsbDeviceAction action)
    {
        if (_hostShutdownInProgress || _usbDeviceOperation is { IsCompleted: false } ||
            _usbDeviceReleaseFailure is not null) return;
        if (sender is not FrameworkElement { DataContext: UsbDeviceItemView item } ||
            item.SkybridgeUdid is not { } udid || item.SkybridgeFingerprint is not { } fingerprint ||
            item.SkybridgeDeviceId is not { } deviceId ||
            !(action switch
            {
                UsbDeviceAction.Pair => item.CanPairSkybridge,
                UsbDeviceAction.Connect => item.CanConnectSkybridge,
                UsbDeviceAction.Disconnect => item.CanDisconnectSkybridge,
                _ => false
            })) return;
        bool pairing = action == UsbDeviceAction.Pair;
        if (action != UsbDeviceAction.Disconnect &&
            (pairing ? !ViewModel.AccountSession.IsSignedIn : ViewModel.AccountSession.ReadAudioReceiverAccount() is null))
        {
            ViewModel.ReportUsbManagementStatus(RemoteControlText(pairing ? "UsbPairSignIn" : "UsbConnectSignIn"));
            ViewModel.ToggleAccountOverlay();
            return;
        }
        var cancellation = new CancellationTokenSource();
        _usbDeviceCancellation = cancellation;
        _usbDeviceRequiresOnline = pairing;
        UsbDevicesInteraction.IsEnabled = false;
        _usbDeviceOperation = action switch
        {
            UsbDeviceAction.Pair => PairUsbFromWindowAsync(udid, fingerprint, deviceId, cancellation.Token),
            UsbDeviceAction.Connect => ConnectUsbFromWindowAsync(udid, fingerprint, deviceId, cancellation.Token),
            UsbDeviceAction.Disconnect => DisconnectUsbFromWindowAsync(item, cancellation.Token),
            _ => throw new ArgumentOutOfRangeException(nameof(action))
        };
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
            ViewModel.UpdateUsbConnections(_remoteControlWorkspace.ReadUsbControlSessions());
        }
    }

    private async Task DisconnectUsbFromWindowAsync(UsbDeviceItemView item, CancellationToken token)
    {
        try
        {
            var selected = _remoteControlWorkspace.ReadUsbControlSessions().SingleOrDefault(peer =>
                peer.SessionId == item.SkybridgeSessionId && peer.Route.Udid == item.SkybridgeUdid &&
                peer.Route.Fingerprint == item.SkybridgeFingerprint && peer.Route.PeerDeviceId == item.SkybridgeDeviceId);
            if (selected is null)
            {
                ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbDisconnectChanged"));
                return;
            }
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbDisconnectPending"));
            await _remoteControlWorkspace.DisconnectUsbControlAsync(selected.Route, selected.SessionId, token);
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbDisconnectReady"));
        }
        catch (Exception error)
        {
            WindowsRuntimeLog.Write(error is OperationCanceledException or UsbControlSessionChangedException
                ? WindowsLogLevel.Info : WindowsLogLevel.Error, "UsbDisconnect", error.GetType().Name);
            if (!_hostShutdownInProgress)
                ViewModel.ReportUsbManagementStatus(RemoteControlText(error switch
                {
                    OperationCanceledException => "UsbDisconnectCanceled",
                    UsbControlSessionChangedException => "UsbDisconnectChanged",
                    _ => "UsbDisconnectFailed"
                }));
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
