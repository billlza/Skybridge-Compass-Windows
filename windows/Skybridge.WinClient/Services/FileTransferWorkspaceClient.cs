using System.Runtime.Versioning;
using Skybridge.WinClient.Services.FileTransfer;
using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal abstract record FileRecipientSelection
{
    internal sealed record Connected(LanFileRecipient Recipient) : FileRecipientSelection;
    internal sealed record WebRtc(WindowsWebRtcFileRecipient Recipient) : FileRecipientSelection;
    internal sealed record Discovered(DiscoveryBrowserPeerCandidate Candidate) : FileRecipientSelection;
}

internal interface IFileTransferSelectionClient
{
    Task<IReadOnlyList<string>> SelectPathsAsync(bool folder, CancellationToken cancellationToken);
    Task<DiscoveryBrowserPeerCandidate?> SelectPeerAsync(CancellationToken cancellationToken);
    async Task<FileRecipientSelection?> SelectRecipientAsync(IReadOnlyList<LanFileRecipient> connected, WindowsWebRtcFileRecipient? webRtc, CancellationToken cancellationToken)
    {
        var candidate = await SelectPeerAsync(cancellationToken);
        return candidate is null ? null : new FileRecipientSelection.Discovered(candidate);
    }
    Task<bool> ApproveIncomingAsync(ClassicFileMetadata metadata, string destinationDirectory, CancellationToken cancellationToken);
    string DestinationDirectory { get; }
}

/// <summary>Live transfer workspace. Identities and control sessions belong to WindowsDeviceWorkspace.</summary>
[SupportedOSPlatform("windows10.0.19041")]
internal sealed class FileTransferWorkspaceClient : IFileTransferWorkspaceClient, IAsyncDisposable
{
    private readonly WindowsDeviceWorkspace _workspace;
    private readonly WindowsLiveConnectionCodes? _codes;
    private readonly IFileTransferSelectionClient _selection;
    private readonly Func<RemoteControlViewerAccount?> _account;
    private readonly Func<string, string> _text;
    private readonly object _state = new();
    private readonly SemaphoreSlim _outbound = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private CancellationTokenSource _connectionsLifetime = new();
    private readonly Dictionary<string, FileTransferQueueItem> _active = new(StringComparer.Ordinal);
    private readonly List<FileTransferHistoryItem> _history = [];
    private readonly HashSet<string> _connected = new(StringComparer.Ordinal);
    private readonly List<Task> _observations = [];
    private readonly TransferProgress _progress;
    private ClassicFileTransferListener? _listener;
    private Task _listenerObservation = Task.CompletedTask;
    private long _lastProgress;
    private bool _disposed;
    private int _disconnecting;
    private string? _destinationDirectory;
    private string _status;

    internal FileTransferWorkspaceClient(WindowsDeviceWorkspace workspace, IFileTransferSelectionClient selection,
        Func<RemoteControlViewerAccount?> account, Func<string, string> text, WindowsLiveConnectionCodes? codes = null)
    {
        _workspace = workspace; _codes = codes; _selection = selection; _account = account; _text = text;
        _status = text("FileTransferLiveReady");
        _progress = new(ReportProgress);
    }

    internal event Action<FileTransferWorkspaceSnapshot, string>? Changed;
    public static string DefaultInitialStatus => "Ready";
    public static string DefaultPendingStatus => "Refreshing...";
    public static string DefaultCompletedStatusMessage => "File transfer workspace updated";
    public static string DefaultSelectFilesPendingStatus => "Preparing file picker...";
    public static string DefaultSelectFolderPendingStatus => "Preparing folder picker...";
    public static string DefaultShareQrPendingStatus => "Preparing QR...";
    public static string BuildDefaultCompletedStatus(FileTransferWorkspaceSnapshot snapshot) => $"Snapshot {snapshot.CapturedAt:HH:mm:ss} UTC";
    public static FileTransferWorkspaceActionResult BuildDefaultSelectFilesActionResult() => new("Unavailable", "File picker is not configured.", "");
    public static FileTransferWorkspaceActionResult BuildDefaultSelectFolderActionResult() => new("Unavailable", "Folder picker is not configured.", "");
    public static FileTransferWorkspaceActionResult BuildDefaultShareQrActionResult() => new("Unavailable", "QR sharing is not available for the current LAN transfer session.", "");
    public string BuildInitialStatus() => _text("FileTransferLiveReady");
    public string BuildPendingStatus() => DefaultPendingStatus;
    public string BuildCompletedStatus(FileTransferWorkspaceSnapshot snapshot) { lock (_state) return _status; }
    public string BuildCompletedStatusMessage() => DefaultCompletedStatusMessage;
    public bool CanSelectFiles() => !_disposed;
    public bool CanSelectFolder() => !_disposed;
    public bool CanGenerateShareQr() => false;
    public string BuildSelectFilesPendingStatus() => DefaultSelectFilesPendingStatus;
    public string BuildSelectFolderPendingStatus() => DefaultSelectFolderPendingStatus;
    public string BuildShareQrPendingStatus() => DefaultShareQrPendingStatus;
    public Task<FileTransferWorkspaceSnapshot> BuildReadOnlySnapshotAsync() => Task.FromResult(Snapshot());
    public Task<FileTransferWorkspaceActionResult> BuildSelectFilesActionAsync() => SelectAndSendAsync(false);
    public Task<FileTransferWorkspaceActionResult> BuildSelectFolderActionAsync() => SelectAndSendAsync(true);
    public Task<FileTransferWorkspaceActionResult> BuildShareQrActionAsync() => Task.FromResult(BuildDefaultShareQrActionResult());

    private CancellationTokenSource? _passiveScope;
    private Task _passiveRun = Task.CompletedTask;
    internal bool HasPassiveReception => Volatile.Read(ref _passiveScope) != null;

    internal async Task StartPassiveReceptionAsync(RemoteControlNetworkInterface network, Audio.AccountAudioAuthorization accountOwner,
        ILanPibApprovalPresenter pairing)
    {
        if (!await _outbound.WaitAsync(0)) throw new InvalidOperationException(_text("FileTransferLiveBusy"));
        try
        {
            var account = RequireAccount(); accountOwner.RequireCurrent();
            if (HasPassiveReception) throw new InvalidOperationException(_text("FileTransferLiveBusy"));
            var destination = ClassicFileTransferReceiver.ValidateReceiveDirectory(_selection.DestinationDirectory);
            var scope = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, _connectionsLifetime.Token);
            ClassicFileTransferListener? receiver = null;
            try
            {
                receiver = new(_workspace.RequireIncomingControlSession, destination, _selection.ApproveIncomingAsync, _progress,
                    (meta, result, failure) => Complete(meta?.TransferId, meta?.FileName, result, failure), scope.Token, network.Address, accountOwner.RequireCurrent);
                await _workspace.StartIncomingMainAsync(network, account, accountOwner, pairing, scope.Token, receiver.BoundListener);
                _passiveScope = scope;
                _passiveRun = ObservePassiveReceptionAsync(receiver, scope, _workspace.IncomingMainEnded);
                SetStatus(_text("FileReceiveWaiting"));
            }
            catch
            {
                scope.Cancel();
                if (receiver != null) await receiver.DisposeAsync();
                scope.Dispose();
                throw;
            }
        }
        finally { _outbound.Release(); }
    }

    private async Task ObservePassiveReceptionAsync(ClassicFileTransferListener receiver, CancellationTokenSource scope, Task<Exception?> mainEnded)
    {
        await Task.WhenAny(receiver.Completion, mainEnded).ConfigureAwait(false);
        scope.Cancel();
        var errors = new List<Exception>();
        try { await _workspace.StopIncomingMainAsync(filesOnly: true).ConfigureAwait(false); } catch (Exception e) { errors.Add(e); }
        try { await receiver.DisposeAsync().ConfigureAwait(false); } catch (Exception e) { errors.Add(e); }
        if (errors.Count != 0)
        {
            var failure = new AggregateException("LAN file reception could not fully stop.", errors);
            SetStatus(failure.Message);
            throw failure;
        }
        SetStatus(_text("FileReceiveStopped"));
    }

    internal async Task StopPassiveReceptionAsync()
    {
        await _outbound.WaitAsync();
        try { await StopPassiveOwnerAsync(); }
        finally { _outbound.Release(); }
    }
    private async Task StopPassiveOwnerAsync()
    {
        if (_passiveScope is not { } scope) return;
        scope.Cancel();
        await _passiveRun;
        _passiveScope = null; scope.Dispose();
    }

    internal async Task ConnectSelectedPeerAsync()
    {
        if (!await _outbound.WaitAsync(0)) throw new InvalidOperationException(_text("FileTransferLiveBusy"));
        try
        {
            var account = RequireAccount();
            var peer = await _selection.SelectPeerAsync(_lifetime.Token);
            if (peer is not null) await ConnectAsync(peer, account);
        }
        catch (Exception failure) { SetStatus(failure.Message); throw; }
        finally { _outbound.Release(); }
    }

    internal async Task DisconnectAsync()
    {
        if (Interlocked.Exchange(ref _disconnecting, 1) != 0) throw new InvalidOperationException(_text("FileTransferLiveBusy"));
        try
        {
            _connectionsLifetime.Cancel();
            await _outbound.WaitAsync();
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                await StopPassiveOwnerAsync();
                await _workspace.DisconnectControlSessionsAsync();
                if (_listener is { } listener) { await listener.DisposeAsync(); _listener = null; }
                await _listenerObservation;
                await Task.WhenAll(_observations);
                _observations.Clear();
                _connectionsLifetime.Dispose();
                _connectionsLifetime = new();
                SetStatus(_text("FileTransferLiveDisconnected"));
            }
            finally { _outbound.Release(); }
        }
        finally { Volatile.Write(ref _disconnecting, 0); }
    }

    internal Task<FileTransferWorkspaceActionResult> SendSelectedPathsAsync(IReadOnlyList<string> paths, bool folder) => SelectAndSendAsync(folder, paths);

    private async Task<FileTransferWorkspaceActionResult> SelectAndSendAsync(bool folder, IReadOnlyList<string>? selectedPaths = null)
    {
        if (!await _outbound.WaitAsync(0)) throw new InvalidOperationException(_text("FileTransferLiveBusy"));
        string? staging = null;
        try
        {
            var account = RequireAccount();
            var paths = selectedPaths ?? await _selection.SelectPathsAsync(folder, _lifetime.Token);
            if (paths.Count == 0) return Result("FileTransferLiveCancelled");
            if (paths.Count > 64 || (folder && paths.Count != 1) || paths.Any(string.IsNullOrWhiteSpace))
                throw new InvalidOperationException(_text("FileTransferLiveSelectionLimit"));
            using var batch = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token, _connectionsLifetime.Token);
            var choice = await _selection.SelectRecipientAsync(_workspace.ConnectedFileRecipients(account), _codes?.FileRecipient, batch.Token);
            if (choice is null) return Result("FileTransferLiveCancelled");
            batch.Token.ThrowIfCancellationRequested();
            if (RequireAccount().NebulaId != account.NebulaId)
                throw new InvalidOperationException(_text("FileTransferLiveSignIn"));
            Func<string, string, CancellationToken, Task<ClassicFileTransferResult>> send;
            CancellationToken lifetime = batch.Token;
            switch (choice)
            {
                case FileRecipientSelection.Connected live:
                    var connected = _workspace.RequireConnectedFileRecipient(live.Recipient, account);
                    lifetime = connected.Lifetime;
                    send = (id,path,ct) => ClassicFileTransferSender.SendToRecipientAsync(connected, live.Recipient, id, path, _progress, ct);
                    break;
                case FileRecipientSelection.WebRtc online:
                    var codes = _codes ?? throw new InvalidOperationException(_text("FileTransferLiveNoPeers"));
                    send = (id,path,ct) => codes.SendFileAsync(online.Recipient, id, path, new TransferProgress(ReportWebRtcProgress), ct);
                    break;
                case FileRecipientSelection.Discovered discovery:
                    var session = await ConnectAsync(discovery.Candidate, account);
                    session.RequireFileTransferRoute(discovery.Candidate);
                    var recipient = session.CurrentFileRecipient() ?? throw new InvalidOperationException(_text("FileTransferLiveNoPeers"));
                    if (recipient.Port != discovery.Candidate.Routes.FileTransfer?.Port)
                        throw new InvalidOperationException(_text("FileTransferLiveNoPeers"));
                    lifetime = session.Lifetime;
                    send = (id,path,ct) => ClassicFileTransferSender.SendToRecipientAsync(session, recipient, id, path, _progress, ct);
                    break;
                default: throw new InvalidOperationException("Unknown file recipient selection.");
            }
            using var admission = CancellationTokenSource.CreateLinkedTokenSource(batch.Token, lifetime);
            using var power = WindowsPowerKeepAwake.Arm();
            if (folder)
            {
                SetStatus(_text("FileTransferLivePackaging"));
                staging = Path.Combine(Path.GetTempPath(), "SkyBridgeTransfer-" + Guid.NewGuid().ToString("N"));
                paths = [await FileTransferFolderArchive.CreateAsync(paths[0], staging, admission.Token)];
            }
            foreach (var path in paths) await SendFileAsync(send, path, admission.Token);
            return Result("FileTransferLiveCompleted");
        }
        catch (Exception failure)
        {
            SetStatus(failure.Message);
            try { if (staging is not null && Directory.Exists(staging)) Directory.Delete(staging, recursive: true); staging = null; }
            catch (Exception cleanup) { throw new AggregateException("Transfer and selected-folder staging cleanup failed.", failure, cleanup); }
            throw;
        }
        finally
        {
            try { if (staging is not null) Directory.Delete(staging, recursive: true); }
            finally { _outbound.Release(); }
        }
    }

    private async Task SendFileAsync(Func<string, string, CancellationToken, Task<ClassicFileTransferResult>> send, string path, CancellationToken token)
    {
        var transferId = Guid.NewGuid().ToString("D");
        try
        {
            SetStatus(_text("FileTransferLiveSending"));
            var result = await send(transferId, path, token);
            Complete(transferId, Path.GetFileName(path), result, null);
        }
        catch (Exception failure) { Complete(transferId, Path.GetFileName(path), null, failure); throw; }
    }

    private RemoteControlViewerAccount RequireAccount()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Volatile.Read(ref _disconnecting) != 0) throw new InvalidOperationException(_text("FileTransferLiveBusy"));
        return _account() ?? throw new InvalidOperationException(_text("FileTransferLiveSignIn"));
    }

    private async Task<LanProductControlSession> ConnectAsync(DiscoveryBrowserPeerCandidate peer, RemoteControlViewerAccount account)
    {
        if (_listener is null)
        {
            _destinationDirectory = Path.GetFullPath(_selection.DestinationDirectory);
            if (!Directory.Exists(_destinationDirectory)) throw new DirectoryNotFoundException(_text("FileTransferLiveMissingDestination"));
            _listener = new(_workspace.RequireIncomingControlSession, _destinationDirectory, _selection.ApproveIncomingAsync, _progress,
                (metadata, result, failure) => Complete(metadata?.TransferId, metadata?.FileName, result, failure), _lifetime.Token);
            _listenerObservation = ObserveListenerAsync(_listener);
        }
        if (_listener.Completion.IsCompleted) throw new IOException(_text("FileTransferLiveListenerStopped"));
        SetStatus(_text("FileTransferLiveConnecting"));
        var session = await _workspace.ConnectControlAsync(peer, account, _listener.Port, _connectionsLifetime.Token);
        bool added;
        lock (_state) added = _connected.Add(session.SessionId);
        if (added)
        {
            _observations.RemoveAll(task => task.IsCompletedSuccessfully);
            _observations.Add(ObserveSessionAsync(session));
        }
        SetStatus(_text("FileTransferLiveConnected"));
        return session;
    }

    private async Task ObserveSessionAsync(LanProductControlSession session)
    {
        var failure = await session.Completion.ConfigureAwait(false);
        lock (_state) _connected.Remove(session.SessionId);
        if (!_lifetime.IsCancellationRequested) SetStatus(failure?.Message ?? _text("FileTransferLiveDisconnected"));
    }

    private async Task ObserveListenerAsync(ClassicFileTransferListener listener)
    {
        try { await listener.Completion.ConfigureAwait(false); }
        catch (Exception failure) { _connectionsLifetime.Cancel(); SetStatus(failure.Message); }
    }

    private void ReportProgress(ClassicFileTransferProgress progress) => ReportProgress(progress, "LAN · PQC");
    private void ReportProgress(ClassicFileTransferProgress progress, string binding)
    {
        bool publish;
        lock (_state)
        {
            _active[progress.TransferId] = new(progress.FileName, progress.IsIncoming ? "Receiving" : "Sending",
                $"{progress.Bytes:N0} / {progress.TotalBytes:N0} B", binding, "");
            var now = Environment.TickCount64;
            publish = now - _lastProgress >= 100 || progress.Bytes == progress.TotalBytes;
            if (publish) _lastProgress = now;
        }
        if (publish) Publish();
    }

    internal void CompleteIncomingWebRtc(ClassicFileMetadata metadata, ClassicFileTransferResult? result, Exception? failure) =>
        Complete(metadata.TransferId, metadata.FileName, result, failure);
    internal void ReportWebRtcProgress(ClassicFileTransferProgress progress) => ReportProgress(progress, "WebRTC · PQC");
    private void Complete(string? transferId, string? name, ClassicFileTransferResult? result, Exception? failure)
    {
        lock (_state)
        {
            if (transferId is not null) _active.Remove(transferId);
            _status = failure?.Message ?? _text("FileTransferLiveCompleted");
            _history.Insert(0, new(name ?? _text("FileTransferLiveIncoming"),
                failure is null ? (result?.SavedPath is null ? "Sent" : "Received") : "Failed",
                result?.FileHash ?? "", result?.SavedPath ?? failure?.Message ?? _text("FileTransferLiveReceiptVerified")));
            if (_history.Count > 100) _history.RemoveRange(100, _history.Count - 100);
        }
        Publish();
    }

    private FileTransferWorkspaceSnapshot Snapshot()
    {
        lock (_state) return new(DateTimeOffset.UtcNow, _active.Values.ToArray(), _history.ToArray(),
            [new(_text("FileTransferLiveConnectionLabel"), _connected.Count.ToString(), _text("FileTransferLiveProtocol")),
             new(_text("FileTransferLiveDestinationLabel"), _destinationDirectory ?? _text("FileTransferLiveDestinationPending"), _text("FileTransferLiveReceiptVerified"))]);
    }
    private FileTransferWorkspaceActionResult Result(string key) { SetStatus(_text(key)); return new(_text(key), _text(key), ""); }
    private void SetStatus(string status) { lock (_state) _status = status; Publish(); }
    private void Publish() { var snapshot = Snapshot(); string status; lock (_state) status = _status; Changed?.Invoke(snapshot, status); }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _lifetime.Cancel();
        _connectionsLifetime.Cancel();
        await _outbound.WaitAsync();
        try
        {
            await StopPassiveOwnerAsync();
            if (_listener is { } listener) { await listener.DisposeAsync(); _listener = null; }
            await _listenerObservation;
            await _workspace.DisconnectControlSessionsAsync();
            await Task.WhenAll(_observations);
            _disposed = true;
            _lifetime.Dispose();
            _connectionsLifetime.Dispose();
        }
        finally { _outbound.Release(); }
    }

    private sealed class TransferProgress(Action<ClassicFileTransferProgress> report) : IProgress<ClassicFileTransferProgress>
    { public void Report(ClassicFileTransferProgress value) => report(value); }
}
