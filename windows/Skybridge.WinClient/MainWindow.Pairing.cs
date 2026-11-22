using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Skybridge.WinClient.Services;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private async Task<WebRtcComparison> CompareWebRtcPairingAsync(string device, string digits, CancellationToken token)
    {
        var result = await _dialogs.ShowAsync(() =>
        {
            token.ThrowIfCancellationRequested();
            RestoreMainWindow();
            var body = new StackPanel { Spacing = 12 };
            var code = new TextBlock { Text = digits, FontSize = 32, IsTextSelectionEnabled = true };
            AutomationProperties.SetAutomationId(code, "Skybridge.WebRtcPairing.SasCode");
            body.Children.Add(new TextBlock { Text = device, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(code);
            body.Children.Add(new TextBlock { Text = RemoteControlText("WebRtcPairingCompare"), TextWrapping = TextWrapping.Wrap });
            var dialog = new ContentDialog
            {
                XamlRoot = RootShell.XamlRoot, Title = RemoteControlText("LanPairingTitle"), Content = body,
                PrimaryButtonText = RemoteControlText("WebRtcPairingRemember"), SecondaryButtonText = RemoteControlText("WebRtcPairingOnce"),
                CloseButtonText = RemoteControlText("WebRtcPairingMismatch"), DefaultButton = ContentDialogButton.Close
            };
            return new NativeWindowDialog(dialog);
        }, token).ConfigureAwait(false);
        return result switch { WindowDialogResult.Primary => WebRtcComparison.Remember,
            WindowDialogResult.Secondary => WebRtcComparison.AllowOnce, _ => WebRtcComparison.Reject };
    }

    private sealed class NativePairingApproval(MainWindow window) : ILanPibApprovalPresenter
    {
        public async Task<bool> ShowAsync(LanPibApprovalRequest request, CancellationToken token)
        {
            return await window._dialogs.ShowAsync(() =>
            {
                request.RequireCurrent(); window.RestoreMainWindow();
                var content = new StackPanel { Spacing = 12 };
                var code = new TextBlock { Text = request.SasCode, FontSize = 32, IsTextSelectionEnabled = true };
                AutomationProperties.SetAutomationId(code, "Skybridge.Pairing.SasCode");
                content.Children.Add(code);
                content.Children.Add(new TextBlock
                {
                    Text = window.RemoteControlText("LanPairingCompare"),
                    TextWrapping = TextWrapping.Wrap
                });
                content.Children.Add(new TextBlock
                {
                    Text = request.Request.RequesterDeviceId + "\n" + request.Request.RequesterProtocolIdentityFingerprint,
                    TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true
                });
                content.Children.Add(new TextBlock
                {
                    Text = window.RemoteControlText("LanPairingSaveDetail"),
                    TextWrapping = TextWrapping.Wrap
                });
                var dialog = new ContentDialog
                {
                    XamlRoot = window.RootShell.XamlRoot, Title = window.RemoteControlText("LanPairingTitle"), Content = content,
                    PrimaryButtonText = window.RemoteControlText("LanPairingSave"),
                    CloseButtonText = window.RemoteControlText("LanPairingReject"), DefaultButton = ContentDialogButton.Close
                };
                AutomationProperties.SetAutomationId(dialog, "Skybridge.Pairing.Approval");
                return new NativeWindowDialog(dialog);
            }, token).ConfigureAwait(false) == WindowDialogResult.Primary;
        }
    }
}
