using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private AudioReceiveHost? _audioReceiveHost;
    private AudioPlaybackApprovalService? _audioApprovals;
    private DispatcherTimer? _audioStatusTimer;
    private CancellationTokenSource? _audioCatalogCancellation;
    private Task<IReadOnlyList<AudioOutputEndpoint>>? _audioCatalogTask;
    private Task<IReadOnlyList<RemoteControlNetworkInterface>>? _audioNetworksTask;
    private AccountAudioAuthorization? _audioListenerEpoch;
    private Task _audioUiOperation = Task.CompletedTask;
    private Exception? _audioCatalogObservedFailure;
    // Retain uncertain native metadata owners; another refresh cannot replace them.
    private AudioOutputCatalogCleanupException? _audioCatalogUnreleased;
    private string? _audioUiError;
    private bool _audioChanging;

    private void ConfigureAudioReception()
    {
        var membership = _audioMembership ?? throw new InvalidOperationException("Audio account authorization is not configured.");
        _audioApprovals = new(new NativeAudioApproval(this));
        _audioReceiveHost = new((session, endpoint) => new(session,
            (inbox, token) => membership.LeaseAsync(inbox, token), _ => Task.FromResult(endpoint), _audioApprovals,
            originalFiles: _remoteControlWorkspace.OriginalAudioFiles), _remoteControlWorkspace.OriginalAudioFiles);
        _remoteControlWorkspace.ConfigureAudioReception(_audioReceiveHost);
        AutomationProperties.SetName(AudioOutputPicker, RemoteControlText("AudioReceiveOutputLabel"));
        AutomationProperties.SetName(AudioNetworkPicker, RemoteControlText("AudioReceiveNetworkLabel"));
        _audioStatusTimer = new() { Interval = TimeSpan.FromMilliseconds(250) };
        _audioStatusTimer.Tick += OnAudioStatusTick; _audioStatusTimer.Start();
        UpdateAudioStatus();
    }
    private async void OnAudioStatusTick(object? sender, object args)
    {
        if (!_audioChanging && !_hostShutdownInProgress && _audioListenerEpoch is { IsCurrent: false })
        {
            _audioUiOperation = StopRevokedAudioAsync();
            await _audioUiOperation;
            return;
        }
        UpdateAudioStatus();
    }
    private async Task StopRevokedAudioAsync()
    {
        _audioListenerEpoch = null; _audioChanging = true;
        try { await StopAudioInputsAsync(); }
        catch (Exception error) { _audioUiError = AudioFailureText(error); WindowsRuntimeLog.Write(WindowsLogLevel.Error, "AudioAccountStop", error.GetType().Name); }
        finally { _audioChanging = false; UpdateAudioStatus(); }
    }
    private void OnAudioOutputChanged(object sender, SelectionChangedEventArgs args) => UpdateAudioStatus();
    private void UpdateAudioStatus()
    {
        if (_audioReceiveHost is not { } host) return;
        var state = host.ReadSnapshot();
        var incoming = _remoteControlWorkspace.ReadIncomingMain();
        AudioOutputPicker.IsEnabled = !_audioChanging && !state.Enabled && !state.Stopping && state.NativeReleaseConfirmed &&
            !_remoteControlWorkspace.HasIncomingMain;
        AudioNetworkPicker.IsEnabled = AudioOutputPicker.IsEnabled;
        AudioOutputRefresh.IsEnabled = AudioOutputPicker.IsEnabled && _audioCatalogUnreleased is null;
        AudioReceiveStart.IsEnabled = AudioOutputPicker.IsEnabled && _audioCatalogUnreleased is null && ViewModel.IsSignedIn &&
            AudioOutputPicker.SelectedItem is ComboBoxItem { Tag: AudioOutputEndpoint } &&
            AudioNetworkPicker.SelectedItem is ComboBoxItem { Tag: RemoteControlNetworkInterface };
        AudioReceiveStop.IsEnabled = !_audioChanging && (state.Enabled || state.Stopping || state.Phase is not null || _remoteControlWorkspace.HasIncomingMain);
        AudioConnectionCopy.IsEnabled = !_audioChanging && !_hostShutdownInProgress &&
            _audioListenerEpoch is { IsCurrent: true } && incoming is { Endpoint: not null, Stopping: false, ReleaseUnconfirmed: false };
        string text;
        bool ordinaryStop = state.Failure is AudioCaptureReceiveException { Reason: AudioStreamingStopReason.UserStopped or AudioStreamingStopReason.ReceiverDeclined }
            or LanAudioStreamException { Reason: AudioStreamingStopReason.UserStopped or AudioStreamingStopReason.ReceiverDeclined };
        bool ordinaryPairingEnd = incoming?.Failure is LanPibRejectedException
            { Code: "userRejected" or "expired" or "transactionMissingOrExpired" };
        bool failed = _audioUiError is not null || incoming?.Failure is not null && !ordinaryPairingEnd ||
            state.Failure is not null && !ordinaryStop || state.NativeReleaseUnconfirmed || _audioCatalogUnreleased is not null;
        if (_audioCatalogUnreleased is not null || state.NativeReleaseUnconfirmed) text = RemoteControlText("AudioReceiveReleaseUnconfirmed");
        else if (_audioUiError is { } localFailure) text = localFailure;
        else if (incoming?.Failure is not null && !ordinaryPairingEnd) text = RemoteControlText("AudioReceiveConnectionFailed");
        else if (state.Failure is not null) text = AudioFailureText(state.Failure);
        else if (state.Stopping) text = RemoteControlText("AudioReceiveStopping");
        else if (state.Phase is { } phase) text = RemoteControlText(phase switch
        {
            AudioCaptureReceivePhase.AwaitingApproval => "AudioReceiveApprovalPending",
            AudioCaptureReceivePhase.ReceivingFile => "AudioReceiveReceivingFile",
            AudioCaptureReceivePhase.Playing => "AudioReceivePlaying",
            AudioCaptureReceivePhase.Finishing => "AudioReceiveFinishing",
            AudioCaptureReceivePhase.Stopping => "AudioReceiveStopping",
            _ => "AudioReceivePreparing"
        }) + (state.PeerName is null ? "" : $" · {state.PeerName}");
        else if (state.Enabled) text = RemoteControlText(state.ListeningDevices > 0 ? "AudioReceiveWaiting" :
            ordinaryPairingEnd ? "LanPairingEnded" : "AudioReceiveNoConnectedDevice");
        else text = RemoteControlText("AudioReceiveDisabled");
        if (incoming?.Endpoint is { } address) text += $"\n{RemoteControlText("AudioReceiveListeningAt")} {address}";
        AudioReceiveStatus.Message = text;
        AudioReceiveStatus.Severity = failed ? InfoBarSeverity.Error : InfoBarSeverity.Informational;
    }
    private string AudioFailureText(Exception error)
    {
        var reason = error is AudioCaptureReceiveException capture ? capture.Reason :
            error is LanAudioStreamException stream ? stream.Reason : (AudioStreamingStopReason?)null;
        return RemoteControlText(reason switch
        {
            AudioStreamingStopReason.UnsupportedOutput => "AudioReceiveUnsupportedOutput",
            AudioStreamingStopReason.AccountRevoked or AudioStreamingStopReason.PermissionRevoked => "AudioReceiveAuthorizationEnded",
            AudioStreamingStopReason.ReceiverDeclined or AudioStreamingStopReason.UserStopped => "AudioReceiveRequestEnded",
            AudioStreamingStopReason.ContentMismatch or AudioStreamingStopReason.ProtocolViolation => "AudioReceiveContentFailed",
            _ => "AudioReceiveFailed"
        });
    }
    private async void OnAudioOutputsRefresh(object sender, RoutedEventArgs args)
    {
        if (_audioChanging || _hostShutdownInProgress) return;
        _audioUiOperation = RefreshAudioDevicesAsync();
        await _audioUiOperation;
    }
    private async Task RefreshAudioDevicesAsync()
    {
        if (_audioChanging || _hostShutdownInProgress || _audioCatalogUnreleased is not null) return;
        _audioChanging = true; _audioUiError = null; UpdateAudioStatus();
        _audioCatalogCancellation = new();
        try
        {
            string? selected = (AudioOutputPicker.SelectedItem as ComboBoxItem)?.Tag is AudioOutputEndpoint old ? old.EndpointId : null;
            _audioCatalogTask = ReadAudioOutputsAsync(_audioCatalogCancellation.Token);
            var outputs = await _audioCatalogTask;
            _audioNetworksTask = WindowsDeviceWorkspace.OperatorNetworkInterfacesAsync(_audioCatalogCancellation.Token);
            var networks = await _audioNetworksTask;
            var selectedNetwork = (AudioNetworkPicker.SelectedItem as ComboBoxItem)?.Tag as RemoteControlNetworkInterface;
            AudioNetworkPicker.Items.Clear();
            foreach (var network in networks)
            {
                var item = new ComboBoxItem { Content = network.DisplayName, Tag = network };
                AudioNetworkPicker.Items.Add(item);
                if (network == selectedNetwork) AudioNetworkPicker.SelectedItem = item;
            }
            AudioOutputPicker.Items.Clear();
            foreach (var endpoint in outputs)
            {
                var item = new ComboBoxItem { Content = endpoint.DisplayName, Tag = endpoint };
                ToolTipService.SetToolTip(item, endpoint.IsNameMissing ? RemoteControlText("AudioReceiveUnnamedOutput") + "\n" + endpoint.EndpointId : endpoint.EndpointId);
                AudioOutputPicker.Items.Add(item);
                if (endpoint.EndpointId == selected) AudioOutputPicker.SelectedItem = item;
            }
            if (outputs.Count == 0) _audioUiError = RemoteControlText("AudioReceiveNoOutputs");
            else if (networks.Count == 0) _audioUiError = RemoteControlText("AudioReceiveNoNetworks");
            _audioCatalogObservedFailure = null;
        }
        catch (Exception error)
        {
            _audioCatalogObservedFailure = error;
            if (error is AudioOutputCatalogCleanupException unconfirmed) _audioCatalogUnreleased = unconfirmed;
            _audioUiError = RemoteControlText("AudioReceiveOutputReadFailed");
            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "AudioOutputCatalog", error.GetType().Name);
        }
        finally
        {
            _audioCatalogCancellation.Dispose(); _audioCatalogCancellation = null;
            _audioChanging = false; UpdateAudioStatus();
        }
    }
    private static async Task<IReadOnlyList<AudioOutputEndpoint>> ReadAudioOutputsAsync(CancellationToken token)
    {
        var completion = new TaskCompletionSource<IReadOnlyList<AudioOutputEndpoint>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var worker = new Thread(() =>
        {
            try
            {
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native audio output selection requires Windows.");
                completion.TrySetResult(WindowsExclusivePcmDevice.ReadOutputs(token));
            }
            catch (Exception error) { completion.TrySetException(error); }
        }) { IsBackground = true, Name = "SkyBridge output devices" };
        worker.Start();
        try { return await completion.Task.ConfigureAwait(false); }
        finally { await Task.Run(worker.Join).ConfigureAwait(false); }
    }
    private async void OnAudioReceiveStart(object sender, RoutedEventArgs args)
    {
        if (_audioChanging || _hostShutdownInProgress) return;
        _audioUiOperation = StartAudioInputsAsync();
        await _audioUiOperation;
    }
    private async Task StartAudioInputsAsync()
    {
        if (_audioChanging || _hostShutdownInProgress || !ViewModel.IsSignedIn || _audioReceiveHost is null ||
            AudioOutputPicker.SelectedItem is not ComboBoxItem { Tag: AudioOutputEndpoint output } ||
            AudioNetworkPicker.SelectedItem is not ComboBoxItem { Tag: RemoteControlNetworkInterface network }) return;
        _audioChanging = true; _audioUiError = null; UpdateAudioStatus();
        try
        {
            var account = ReadCurrentDeviceAccount() ?? throw new InvalidOperationException("Sign in before receiving audio.");
            var epoch = ViewModel.AccountSession.ReadAudioAuthorization() ?? throw new InvalidOperationException("Current account authority is unavailable.");
            epoch.RequireCurrent(); _audioListenerEpoch = epoch;
            await _audioReceiveHost.EnableAsync(output.EndpointId, CancellationToken.None);
            try { await _remoteControlWorkspace.StartIncomingMainAsync(network, account, epoch, new NativePairingApproval(this), CancellationToken.None); }
            catch (Exception startFailure)
            {
                try { await StopAudioInputsAsync(); }
                catch (Exception cleanup) { throw new AggregateException("Audio reception start and cleanup failed.", startFailure, cleanup); }
                throw;
            }
        }
        catch (Exception error) { _audioUiError = AudioFailureText(error); WindowsRuntimeLog.Write(WindowsLogLevel.Error, "AudioReception", error.GetType().Name); }
        finally { _audioChanging = false; UpdateAudioStatus(); }
    }
    private async void OnAudioReceiveStop(object sender, RoutedEventArgs args)
    {
        if (_audioChanging || _hostShutdownInProgress) return;
        _audioUiOperation = StopAudioInputsFromUiAsync();
        await _audioUiOperation;
    }
    private async void OnAudioConnectionCopy(object sender, RoutedEventArgs args)
    {
        if (_audioChanging || _hostShutdownInProgress) return;
        _audioUiOperation = CopyAudioConnectionInfoAsync();
        await _audioUiOperation;
    }
    private async Task CopyAudioConnectionInfoAsync()
    {
        _audioChanging = true; UpdateAudioStatus();
        try
        {
            var epoch = _audioListenerEpoch ?? throw new InvalidOperationException("The audio account session has ended.");
            epoch.RequireCurrent();
            var publication = _remoteControlWorkspace.PrepareIncomingMainConnectionInfo();
            await publication.CopyAsync(CopyRemoteControlPairingTextAsync);
            _notifications.Add(RemoteControlText("AudioConnectionCopied"), RemoteControlText("AudioConnectionCopyDetail"), "\uE8C8");
        }
        catch (Exception error)
        {
            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "AudioConnectionCopy", error.GetType().Name);
            _notifications.Add(RemoteControlText("AudioConnectionCopyFailed"), RemoteControlText("AudioConnectionCopyRetry"), "\uEA39");
        }
        finally { _audioChanging = false; UpdateAudioStatus(); }
    }
    private async Task StopAudioInputsFromUiAsync()
    {
        if (_audioChanging || _audioReceiveHost is null) return;
        _audioChanging = true; _audioUiError = null; UpdateAudioStatus();
        try { await StopAudioInputsAsync(); }
        catch (Exception error) { _audioUiError = AudioFailureText(error); WindowsRuntimeLog.Write(WindowsLogLevel.Error, "AudioReception", error.GetType().Name); }
        finally { _audioChanging = false; UpdateAudioStatus(); }
    }
    private async Task StopAudioReceptionAsync()
    {
        if (_audioStatusTimer is { } timer) { timer.Stop(); timer.Tick -= OnAudioStatusTick; _audioStatusTimer = null; }
        var catalogToken = _audioCatalogCancellation?.Token ?? CancellationToken.None;
        _audioCatalogCancellation?.Cancel();
        await _audioUiOperation;
        await StopAudioInputsAsync();
        if (_audioCatalogTask is { } reading)
        {
            try { await reading; }
            catch (OperationCanceledException error) when (error.InnerException is null &&
                error.CancellationToken == catalogToken && catalogToken.IsCancellationRequested) { }
            catch (Exception error) when (ReferenceEquals(error, _audioCatalogObservedFailure) && _audioCatalogUnreleased is null) { }
        }
        if (_audioNetworksTask is { } networks)
        {
            try { await networks; }
            catch (OperationCanceledException) when (catalogToken.IsCancellationRequested) { }
            catch (Exception error) when (ReferenceEquals(error, _audioCatalogObservedFailure)) { }
        }
        if (_audioReceiveHost is { } host) await host.DisposeAsync();
        if (_audioApprovals is { } approvals) await approvals.DisposeAsync();
        if (_audioCatalogUnreleased is not null) throw _audioCatalogUnreleased;
    }
    private async Task StopAudioInputsAsync()
    {
        _audioListenerEpoch = null;
        var failures = new List<Exception>();
        try { await _remoteControlWorkspace.StopIncomingMainAsync(); } catch (Exception error) { failures.Add(error); }
        if (_audioReceiveHost is { } host)
            try { await host.DisableAsync(); } catch (Exception error) { failures.Add(error); }
        if (failures.Count > 0) throw new AggregateException("Audio reception resources remain unresolved.", failures);
    }
    private sealed class NativeAudioApproval(MainWindow window) : IAudioPlaybackApprovalPresenter
    {
        public async Task<bool> ShowAsync(AudioPlaybackApprovalRequest request, CancellationToken token)
        {
            return await window._dialogs.ShowAsync(() =>
            {
                request.RequireCurrent(); window.RestoreMainWindow();
                var source = request.Source switch
                {
                    AudioPlaybackSource.CapturedPcm pcm => $"{pcm.Format.SampleRate:N0} Hz · {pcm.Format.ValidBits} bit · {pcm.Format.Channels} ch · {pcm.Format.Encoding}",
                    AudioPlaybackSource.OriginalFile file => $"{window.RemoteControlText("AudioReceiveOriginalFile")} · {file.Length:N0} {window.RemoteControlText("AudioReceiveBytes")}",
                    _ => throw new InvalidOperationException("The audio presenter received an unsupported source type.")
                };
                string output = request.OutputEndpointId;
                foreach (var item in window.AudioOutputPicker.Items.OfType<ComboBoxItem>())
                    if (item.Tag is AudioOutputEndpoint endpoint && endpoint.EndpointId == request.OutputEndpointId) output = endpoint.DisplayName;
                var details = new TextBlock
                {
                    Text = $"{window._audioReceiveHost?.ReadSnapshot().PeerName}\n{request.Sender.DeviceId}\n{source}\n{output}\n\n{window.RemoteControlText(request.Source is AudioPlaybackSource.OriginalFile ? "AudioReceiveOriginalFileDetail" : "AudioReceiveApprovalDetail")}",
                    TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true
                };
                AutomationProperties.SetAutomationId(details, "Skybridge.Audio.ReceiveApprovalDetails");
                var dialog = new ContentDialog
                {
                    XamlRoot = window.RootShell.XamlRoot, Title = window.RemoteControlText("AudioReceiveApprovalTitle"), Content = details,
                    PrimaryButtonText = window.RemoteControlText("AudioReceiveAllowOnce"), CloseButtonText = window.RemoteControlText("AudioReceiveDecline"),
                    DefaultButton = ContentDialogButton.Close
                };
                AutomationProperties.SetAutomationId(dialog, "Skybridge.Audio.ReceiveApproval");
                return new NativeWindowDialog(dialog);
            }, token).ConfigureAwait(false) == WindowDialogResult.Primary;
        }
    }
}
