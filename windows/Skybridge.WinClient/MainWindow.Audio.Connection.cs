using System.Net.NetworkInformation;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Media.Imaging;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Windows.Storage.Streams;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private readonly CancellationTokenSource _audioQrLifetime = new();
    private LanConnectionInfoPublication? _audioQrPublication;
    private AccountAudioAuthorization? _audioQrEpoch;
    private long _audioQrNetworkRevision;
    private long _audioQrAttemptedRevision = -1;
    private long _audioQrRenderedRevision = -1;
    private bool _audioQrShutdown;

    private void ConfigureAudioConnectionQr()
    {
        AutomationProperties.SetName(AudioConnectionQrImage, RemoteControlText("AudioConnectionQrAccessibleName"));
        NetworkChange.NetworkAddressChanged += OnAudioConnectionNetworkChanged;
    }

    // This callback can run on a native network thread. The existing UI timer
    // coalesces changes, invalidates old pixels and schedules one owned refresh.
    private void OnAudioConnectionNetworkChanged(object? sender, EventArgs args) =>
        Interlocked.Increment(ref _audioQrNetworkRevision);

    private bool CanPublishAudioConnectionQr() => !_audioQrShutdown && !_hostShutdownInProgress &&
        _audioListenerEpoch is { IsCurrent: true } &&
        _remoteControlWorkspace.ReadIncomingMain() is { Endpoint: not null, Stopping: false, ReleaseUnconfirmed: false };

    private bool AudioConnectionQrNeedsRefresh() => CanPublishAudioConnectionQr() &&
        _audioQrAttemptedRevision != Interlocked.Read(ref _audioQrNetworkRevision);

    private void UpdateAudioConnectionQr()
    {
        if (!CanPublishAudioConnectionQr()) { ClearAudioConnectionQr(); return; }
        if (_audioQrPublication is not { } publication) return;
        if (!ReferenceEquals(_audioQrEpoch, _audioListenerEpoch) ||
            _audioQrRenderedRevision != Interlocked.Read(ref _audioQrNetworkRevision))
        { ClearAudioConnectionQr(); return; }
        try { _ = publication.ReadCurrentText(); }
        catch (Exception error)
        {
            ClearAudioConnectionQr();
            _audioQrAttemptedRevision = -1; // Recheck a replaced owner once; failures then wait for retry or a network change.
            WindowsRuntimeLog.Write(WindowsLogLevel.Warning, "AudioConnectionQrExpired", error.GetType().Name);
        }
    }

    private async void OnAudioConnectionQrRetry(object sender, RoutedEventArgs args)
    {
        if (_audioChanging || !CanPublishAudioConnectionQr()) return;
        _audioUiOperation = RefreshAudioConnectionQrAsync();
        await _audioUiOperation;
    }

    private async Task RefreshAudioConnectionQrAsync()
    {
        _audioChanging = true; UpdateAudioStatus();
        try { await RenderAudioConnectionQrAsync(); }
        finally { _audioChanging = false; UpdateAudioStatus(); }
    }

    private async Task RenderAudioConnectionQrAsync()
    {
        ClearAudioConnectionQr();
        long revision = Interlocked.Read(ref _audioQrNetworkRevision);
        _audioQrAttemptedRevision = revision;
        try
        {
            var epoch = _audioListenerEpoch ?? throw new InvalidOperationException("Audio reception has ended.");
            epoch.RequireCurrent();
            var token = _audioQrLifetime.Token;
            var publication = await _remoteControlWorkspace.PrepareIncomingMainConnectionInfoAsync(token);
            var image = await LanConnectionQrCode.RenderAsync(publication, DecodeAudioConnectionQrAsync, token);
            // Network or owner changes during decoding discard this result. A
            // newer network revision is retried by the next UI tick, never shown.
            if (_audioQrShutdown || _hostShutdownInProgress || !ReferenceEquals(epoch, _audioListenerEpoch) ||
                revision != Interlocked.Read(ref _audioQrNetworkRevision)) return;
            epoch.RequireCurrent(); _ = publication.ReadCurrentText();
            _audioQrPublication = publication; _audioQrEpoch = epoch; _audioQrRenderedRevision = revision;
            AudioConnectionQrImage.Source = image;
            AudioConnectionQrPanel.Visibility = Visibility.Visible;
        }
        catch (OperationCanceledException) when (_audioQrLifetime.IsCancellationRequested)
        { ClearAudioConnectionQr(); }
        catch (Exception error)
        {
            ClearAudioConnectionQr();
            if (CanPublishAudioConnectionQr()) AudioConnectionQrNotice.IsOpen = true;
            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "AudioConnectionQr", error.GetType().Name);
        }
    }

    private static async Task<BitmapImage> DecodeAudioConnectionQrAsync(LanConnectionQrImage rendered, CancellationToken token)
    {
        var image = new BitmapImage();
        using var stream = new InMemoryRandomAccessStream();
        using (var writer = new DataWriter(stream.GetOutputStreamAt(0)))
        {
            writer.WriteBytes(rendered.PngBytes);
            await writer.StoreAsync().AsTask(token);
            writer.DetachStream();
        }
        stream.Seek(0);
        await image.SetSourceAsync(stream).AsTask(token);
        return image;
    }

    private void ClearAudioConnectionQr()
    {
        _audioQrPublication = null; _audioQrEpoch = null; _audioQrRenderedRevision = -1;
        AudioConnectionQrImage.Source = null;
        AudioConnectionQrPanel.Visibility = Visibility.Collapsed;
        AudioConnectionQrNotice.IsOpen = false;
    }

    private void BeginStopAudioConnectionQr()
    {
        if (_audioQrShutdown) return;
        _audioQrShutdown = true;
        NetworkChange.NetworkAddressChanged -= OnAudioConnectionNetworkChanged;
        _audioQrLifetime.Cancel();
        ClearAudioConnectionQr();
    }
}
