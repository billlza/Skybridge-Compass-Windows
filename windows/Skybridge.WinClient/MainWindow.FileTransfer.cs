using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private bool _connectingFileTransfer;
    private bool _disconnectingFileTransfer;

    private async void OnFileReceiveClicked(object sender, RoutedEventArgs args)
    {
        if (_hostShutdownInProgress || !FileReceiveButton.IsEnabled) return;
        FileReceiveButton.IsEnabled = false;
        try
        {
            if (_fileTransferWorkspace.HasPassiveReception) { await _fileTransferWorkspace.StopPassiveReceptionAsync(); return; }
            var epoch = ViewModel.AccountSession.ReadAudioAuthorization() ?? throw new InvalidOperationException(RemoteControlText("FileTransferLiveSignIn"));
            var networks = await WindowsDeviceWorkspace.OperatorNetworkInterfacesAsync(CancellationToken.None);
            if (networks.Count == 0) throw new InvalidOperationException(RemoteControlText("FileReceiveNoNetwork"));
            var picker = new ComboBox { MinWidth = 260, DisplayMemberPath = nameof(RemoteControlNetworkInterface.DisplayName),
                ItemsSource = networks, SelectedIndex = networks.Count == 1 ? 0 : -1, PlaceholderText = RemoteControlText("AudioReceiveNetworkLabel") };
            var answer = await _dialogs.ShowAsync(() =>
            {
                epoch.RequireCurrent();
                var dialog = new ContentDialog
                {
                    XamlRoot = RootShell.XamlRoot, Title = RemoteControlText("FileReceiveNetworkTitle"), Content = picker,
                    PrimaryButtonText = RemoteControlText("FileReceiveStart"), CloseButtonText = RemoteControlText("FileTransferLiveCancel"),
                    IsPrimaryButtonEnabled = picker.SelectedItem is RemoteControlNetworkInterface, DefaultButton = ContentDialogButton.Close
                };
                picker.SelectionChanged += (_, _) => dialog.IsPrimaryButtonEnabled = picker.SelectedItem is RemoteControlNetworkInterface;
                return new NativeWindowDialog(dialog);
            }, CancellationToken.None);
            if (answer != WindowDialogResult.Primary || picker.SelectedItem is not RemoteControlNetworkInterface selected) return;
            epoch.RequireCurrent();
            await _fileTransferWorkspace.StartPassiveReceptionAsync(selected, epoch, new NativePairingApproval(this, filesOnly: true));
        }
        catch (Exception failure) { ViewModel.ApplyLiveFileTransfer(await _fileTransferWorkspace.BuildReadOnlySnapshotAsync(), failure.Message); }
        finally
        {
            FileReceiveButton.Content = RemoteControlText(_fileTransferWorkspace.HasPassiveReception ? "FileReceiveStop" : "FileReceiveStart");
            FileReceiveButton.IsEnabled = !_hostShutdownInProgress;
        }
    }

    private void OnFileTransferDragOver(object sender, DragEventArgs args)
    {
        args.AcceptedOperation = !_hostShutdownInProgress && !ViewModel.IsBusy &&
            args.DataView.Contains(StandardDataFormats.StorageItems) ? DataPackageOperation.Copy : DataPackageOperation.None;
    }

    private async void OnFileTransferDrop(object sender, DragEventArgs args)
    {
        var deferral = args.GetDeferral();
        try
        {
            if (_hostShutdownInProgress || !args.DataView.Contains(StandardDataFormats.StorageItems)) return;
            var items = await args.DataView.GetStorageItemsAsync();
            var hasFolder = items.Any(item => item.IsOfType(StorageItemTypes.Folder));
            if (hasFolder && items.Count != 1) throw new InvalidOperationException(RemoteControlText("FileTransferLiveSelectionLimit"));
            var result = await _fileTransferWorkspace.SendSelectedPathsAsync(items.Select(item => item.Path).ToArray(), hasFolder);
            ViewModel.ApplyLiveFileTransfer(await _fileTransferWorkspace.BuildReadOnlySnapshotAsync(), result.Status);
        }
        catch (Exception failure) { ViewModel.ApplyLiveFileTransfer(await _fileTransferWorkspace.BuildReadOnlySnapshotAsync(), failure.Message); }
        finally { deferral.Complete(); }
    }

    private async void OnFileTransferAccountChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs args)
    {
        if (args.PropertyName == nameof(ViewModel.IsSignedIn) && !ViewModel.IsSignedIn && !_hostShutdownInProgress)
            await DisconnectFileTransferAsync();
    }

    private async void OnFileTransferDisconnectClicked(object sender, RoutedEventArgs args) => await DisconnectFileTransferAsync();

    private async Task DisconnectFileTransferAsync()
    {
        if (_disconnectingFileTransfer) return;
        _disconnectingFileTransfer = true;
        FileTransferDisconnectButton.IsEnabled = false;
        try { await _fileTransferWorkspace.DisconnectAsync(); }
        catch (Exception failure) { ViewModel.ApplyLiveFileTransfer(await _fileTransferWorkspace.BuildReadOnlySnapshotAsync(), failure.Message); }
        finally { FileReceiveButton.Content = RemoteControlText(_fileTransferWorkspace.HasPassiveReception ? "FileReceiveStop" : "FileReceiveStart"); _disconnectingFileTransfer = false; if (!_hostShutdownInProgress) FileTransferDisconnectButton.IsEnabled = true; }
    }

    private void OnFileTransferChanged(FileTransferWorkspaceSnapshot snapshot, string status)
    {
        if (!DispatcherQueue.TryEnqueue(() =>
        {
            if (!_hostShutdownComplete)
            {
                ViewModel.ApplyLiveFileTransfer(snapshot, status);
                _notifications.ObserveTransfers(snapshot.History, RemoteControlText, ViewModel.Settings.ShowFileTransferNotifications);
            }
        }) && !_hostShutdownComplete)
            throw new InvalidOperationException("The transfer state could not be presented in the application window.");
    }

    private async void OnFileTransferConnectClicked(object sender, RoutedEventArgs args)
    {
        if (_connectingFileTransfer || _hostShutdownInProgress) return;
        _connectingFileTransfer = true;
        FileTransferConnectButton.IsEnabled = false;
        try { await _fileTransferWorkspace.ConnectSelectedPeerAsync(); }
        catch (Exception failure)
        {
            ViewModel.ApplyLiveFileTransfer(await _fileTransferWorkspace.BuildReadOnlySnapshotAsync(), failure.Message);
        }
        finally { _connectingFileTransfer = false; if (!_hostShutdownInProgress) FileTransferConnectButton.IsEnabled = true; }
    }

    private sealed class NativeFileTransferSelection(MainWindow window) : IFileTransferSelectionClient
    {
        private readonly WindowsDiscoveryBrowserClient _peerDiscovery =
            WindowsNativeRuntimeDependencyFactory.CreateFeaturePeerDiscoveryClient();
        public string DestinationDirectory => Environment.ExpandEnvironmentVariables(window.ViewModel.Settings.DefaultTransferPath);

        public async Task<IReadOnlyList<string>> SelectPathsAsync(bool folder, CancellationToken cancellationToken)
        {
            if (folder)
            {
                var picker = new Microsoft.Windows.Storage.Pickers.FolderPicker(window.AppWindow.Id);
                var selected = await picker.PickSingleFolderAsync().AsTask(cancellationToken);
                return selected is null ? [] : [selected.Path];
            }
            var files = new Microsoft.Windows.Storage.Pickers.FileOpenPicker(window.AppWindow.Id);
            var selection = await files.PickMultipleFilesAsync().AsTask(cancellationToken);
            return selection.Select(file => file.Path).ToArray();
        }

        public async Task<FileRecipientSelection?> SelectRecipientAsync(IReadOnlyList<LanFileRecipient> connected, WindowsWebRtcFileRecipient? webRtc, CancellationToken cancellationToken)
        {
            if (connected.Count > 0 || webRtc != null)
            {
                var names = connected.GroupBy(peer => peer.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                    .Where(group => group.Count() > 1).Select(group => group.Key).ToHashSet(StringComparer.CurrentCultureIgnoreCase);
                var choices = connected.Select(peer => new ConnectedChoice(new FileRecipientSelection.Connected(peer), names.Contains(peer.DisplayName)
                    ? $"{peer.DisplayName} · LAN · {peer.DeviceId}" : $"{peer.DisplayName} · LAN")).ToList();
                if (webRtc is not null) choices.Add(new(new FileRecipientSelection.WebRtc(webRtc), $"{webRtc.Name} · WebRTC"));
                var picker = new ComboBox {
                    MinWidth = 380, DisplayMemberPath = nameof(ConnectedChoice.Name),
                    PlaceholderText = window.RemoteControlText("FileTransferLiveChoosePeer"),
                    ItemsSource = choices
                };
                Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(picker, "Skybridge.FileTransfer.ConnectedPeer");
                var dialog = new ContentDialog {
                    XamlRoot = window.RootShell.XamlRoot, Title = window.RemoteControlText("FileTransferLiveConnectedRecipients"),
                    Content = picker, PrimaryButtonText = window.RemoteControlText("FileTransferLiveSendToSelected"),
                    SecondaryButtonText = window.RemoteControlText("FileTransferLiveDiscoverAnother"),
                    CloseButtonText = window.RemoteControlText("FileTransferLiveCancel"), IsPrimaryButtonEnabled = false
                };
                picker.SelectionChanged += (_, _) => dialog.IsPrimaryButtonEnabled = picker.SelectedItem is ConnectedChoice;
                var result = await window._dialogs.ShowAsync(() => new NativeWindowDialog(dialog), cancellationToken);
                if (result == WindowDialogResult.Primary)
                {
                    var selected = picker.SelectedItem as ConnectedChoice ?? throw new InvalidOperationException("No file receiver was selected.");
                    return selected.Selection;
                }
                if (result != WindowDialogResult.Secondary) return null;
            }
            var candidate = await SelectPeerAsync(cancellationToken);
            return candidate is null ? null : new FileRecipientSelection.Discovered(candidate);
        }

        private sealed record ConnectedChoice(FileRecipientSelection Selection, string Name);

        public async Task<DiscoveryBrowserPeerCandidate?> SelectPeerAsync(CancellationToken cancellationToken)
        {
            // File operations own their discovery result. The UI refresh command may
            // legitimately skip while busy, and its filtered cache is not a lookup result.
            var snapshot = await _peerDiscovery.BuildReadOnlySnapshotAsync(new(
                DiscoveryBrowserAction.Refresh, SkyBridgeProtocolConstants.TcpControlDnsSdService,
                "", "", false, WindowsDiscoveryBrowserClient.DefaultInputPolicy.ExtendedSearchSeconds), cancellationToken);
            var candidates = snapshot.Peers.ToArray();
            var files = candidates.Where(peer => peer.Routes.FileTransfer is not null)
                .DistinctBy(peer => (peer.Peer.DeviceId, peer.Peer.PublicKeyFingerprint, peer.Routes.FileTransfer)).ToArray();
            if (files.Length == 0) throw new InvalidOperationException(window.RemoteControlText("FileTransferLiveNoPeers"));
            var picker = new ComboBox { MinWidth = 380, ItemsSource = files.Select(peer => new PeerChoice(peer, peer.Peer.DisplayName)).ToArray(),
                DisplayMemberPath = nameof(PeerChoice.Name), PlaceholderText = window.RemoteControlText("FileTransferLiveChoosePeer") };
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetAutomationId(picker, "Skybridge.FileTransfer.Peer");
            var dialog = new ContentDialog {
                XamlRoot = window.RootShell.XamlRoot, Title = window.RemoteControlText("FileTransferLiveChoosePeer"), Content = picker,
                PrimaryButtonText = window.RemoteControlText("FileTransferLiveConnect"), CloseButtonText = window.RemoteControlText("FileTransferLiveCancel"),
                IsPrimaryButtonEnabled = false
            };
            picker.SelectionChanged += (_, _) => dialog.IsPrimaryButtonEnabled = picker.SelectedItem is PeerChoice;
            var result = await window._dialogs.ShowAsync(() => new NativeWindowDialog(dialog), cancellationToken);
            if (result != WindowDialogResult.Primary) return null;
            var selected = (picker.SelectedItem as PeerChoice)?.Candidate ?? throw new InvalidOperationException("No transfer peer was selected.");
            return DiscoveryPeerRoutes.JoinFileTransferServices(selected, candidates);
        }

        public async Task<bool> ApproveIncomingAsync(ClassicFileMetadata metadata, string destinationDirectory, CancellationToken cancellationToken)
        {
            return await window._dialogs.ShowAsync(() =>
            {
                var dialog = new ContentDialog
                {
                    XamlRoot = window.RootShell.XamlRoot, Title = window.RemoteControlText("FileTransferLiveIncoming"),
                    Content = new TextBlock { Text = $"{metadata.SenderDeviceName}\n{metadata.FileName}\n{metadata.FileSize:N0} B\n{destinationDirectory}", TextWrapping = TextWrapping.Wrap },
                    PrimaryButtonText = window.RemoteControlText("FileTransferLiveAccept"), CloseButtonText = window.RemoteControlText("FileTransferLiveDecline")
                };
                return new NativeWindowDialog(dialog);
            }, cancellationToken).ConfigureAwait(false) == WindowDialogResult.Primary;
        }

        private sealed record PeerChoice(DiscoveryBrowserPeerCandidate Candidate, string Name);
    }
}
