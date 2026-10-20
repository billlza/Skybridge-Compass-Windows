using Microsoft.UI.Xaml;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.ViewModels;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private Task? _usbPairingOperation;
    private CancellationTokenSource? _usbPairingCancellation;
    private AccountAudioAuthorization? _usbPairingEpoch;
    private Exception? _usbPairingCancellationFailure;

    private async void OnUsbPairClicked(object sender, RoutedEventArgs args)
    {
        if (_hostShutdownInProgress || _usbPairingOperation is { IsCompleted: false } ||
            _usbPairingCancellationFailure is not null) return;
        if (sender is not FrameworkElement { DataContext: UsbDeviceItemView
            { SkybridgeUdid: { } udid, SkybridgeFingerprint: { } fingerprint } }) return;
        if (!ViewModel.AccountSession.IsSignedIn)
        {
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbPairSignIn"));
            ViewModel.ToggleAccountOverlay();
            return;
        }
        var cancellation = new CancellationTokenSource();
        _usbPairingCancellation = cancellation;
        UsbDevicesInteraction.IsEnabled = false;
        _usbPairingOperation = PairUsbFromWindowAsync(udid, fingerprint, cancellation.Token);
        try { await _usbPairingOperation; }
        finally
        {
            _usbPairingEpoch = null;
            // Failed cancellation retains its owner and keeps new work disabled.
            if (_usbPairingCancellationFailure is null)
            {
                _usbPairingCancellation = null;
                cancellation.Dispose();
                UsbDevicesInteraction.IsEnabled = true;
            }
        }
    }

    private async Task PairUsbFromWindowAsync(string udid, string fingerprint, CancellationToken token)
    {
        bool committed = false;
        try
        {
            var account = ViewModel.AccountSession;
            var epoch = account.RequireAudioAuthorization();
            _usbPairingEpoch = epoch;
            var authentication = await account.GetDeviceAuthenticationAsync(token)
                ?? throw new InvalidOperationException("The signed-in account is unavailable.");
            token.ThrowIfCancellationRequested();
            var target = _usbWorkspace.RequireEnrollmentTarget(udid, fingerprint);
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
            WindowsRuntimeLog.Write(error is OperationCanceledException or LanPibRejectedException
                ? WindowsLogLevel.Info : WindowsLogLevel.Error, "UsbPairing", error.GetType().Name);
            if (_hostShutdownInProgress) return;
            string key = committed ? "UsbPairSavedRefreshFailed" :
                _usbPairingCancellationFailure is not null || ProductBootstrapReleaseException.ContainsUnreleasedOwner(error)
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

    private void ObserveUsbPairingAuthorization()
    {
        if (_usbPairingEpoch is { } epoch && (!epoch.IsCurrent || epoch.IsOffline))
            CancelUsbPairing();
    }

    private void CancelUsbPairing()
    {
        if (_usbPairingCancellation is not { } owner || owner.IsCancellationRequested) return;
        try { owner.Cancel(); }
        catch (Exception error)
        {
            _usbPairingCancellationFailure = error;
            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "UsbPairingCancellation", error.GetType().Name);
            ViewModel.ReportUsbManagementStatus(RemoteControlText("UsbPairCleanupFailed"));
        }
    }

    private async Task StopUsbPairingAsync()
    {
        CancelUsbPairing();
        try
        {
            if (_usbPairingOperation is { } operation)
                await operation.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (Exception failure) when (_usbPairingCancellationFailure is { })
        { throw new AggregateException(_usbPairingCancellationFailure, failure); }
        if (_usbPairingCancellationFailure is { } cancellation)
            throw new InvalidOperationException("USB pairing cancellation did not complete cleanly.", cancellation);
    }
}
