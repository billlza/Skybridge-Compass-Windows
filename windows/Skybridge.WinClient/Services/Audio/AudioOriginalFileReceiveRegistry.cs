using System.Net;
using System.Net.Sockets;
using Skybridge.WinClient.Services.FileTransfer;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioOriginalFileReceiveSupport { Unavailable, Wave, WaveAndFlac }

/// <summary>One approved playback offer owns its actual classic producer and file.
/// The shared audio host serializes playback; this registry never grants ordinary
/// file writes or infers authority from a transfer ID alone.</summary>
internal sealed class AudioOriginalFileReceiveRegistry
{
    private readonly object _gate = new();
    private Binding? _binding;
    private Ticket? _current;
    private sealed record Binding(LanProductControlListener Listener, ushort Port, string Directory);

    internal void Bind(LanProductControlListener listener, string privateDirectory)
    {
        var endpoint = (IPEndPoint)listener.RequireLiveListener().LocalEndpoint;
        var directory = ClassicFileTransferReceiver.ValidateReceiveDirectory(privateDirectory);
        lock (_gate)
        {
            if (_binding is not null || _current is not null) throw new InvalidOperationException("An original-file listener or artifact is still owned.");
            _binding = new(listener, checked((ushort)endpoint.Port), directory);
        }
    }
    internal bool CanReceiveFor(LanProductControlSession session)
    {
        Binding? binding; lock (_gate) binding = _binding;
        return binding is not null && binding.Listener.IsListening && session.IsReady && session.LocalFileTransferPort == binding.Port;
    }
    internal AudioOriginalFileReceiveSupport ReceiveSupportFor(LanProductControlSession session)
    {
        if (!CanReceiveFor(session)) return AudioOriginalFileReceiveSupport.Unavailable;
        if (!AudioFlacNative.IsPackaged) return AudioOriginalFileReceiveSupport.Wave;
        AudioFlacNative.RequireCompatible();
        return AudioOriginalFileReceiveSupport.WaveAndFlac;
    }
    internal void Unbind(LanProductControlListener listener)
    {
        Ticket? ticket;
        lock (_gate)
        {
            if (!ReferenceEquals(_binding?.Listener, listener)) return;
            _binding = null; ticket = _current;
        }
        ticket?.Cancel();
    }
    internal Ticket Register(AudioOriginalFileAdmission admission)
    {
        admission.RequireCurrent();
        lock (_gate)
        {
            var binding = _binding ?? throw new InvalidOperationException("Original-file reception is unavailable.");
            if (!binding.Listener.IsListening || admission.Session.LocalFileTransferPort != binding.Port)
                throw new InvalidOperationException("The exact MAIN file endpoint is unavailable.");
            if (_current is not null) throw new InvalidOperationException("Another file playback owner has not released its resources.");
            return _current = new(this, binding.Listener, admission, binding.Directory);
        }
    }
    private void RequireCurrent(Ticket ticket, LanProductControlListener listener)
    {
        lock (_gate)
            if (!ReferenceEquals(_current, ticket) || !ReferenceEquals(_binding?.Listener, listener) || !listener.IsListening)
                throw new InvalidOperationException("The original-file listener or offer changed.");
    }
    private void Remove(Ticket ticket)
    { lock (_gate) if (ReferenceEquals(_current, ticket)) _current = null; }

    // Called by the same bounded TCP listener primitive used by MAIN. This reader
    // owns exactly one metadata frame and hands the remaining stream to its ticket.
    internal async Task ReceiveAsync(TcpClient client, Func<string, LanProductControlSession> resolveSession, CancellationToken token)
    {
        var network = client.GetStream();
        var first = await ClassicFileTransferOperation.ReadAsync(network, TimeSpan.FromSeconds(5), token).ConfigureAwait(false);
        if (first.Type != ClassicFileFrameType.Metadata) throw new InvalidDataException("An audio file connection must start with metadata.");
        var metadata = ClassicFileTransferWire.Decode<ClassicFileMetadata>(first.Payload);
        ClassicFileTransferWire.ValidateMetadata(metadata);
        var session = resolveSession(metadata.SenderDeviceId ?? throw new InvalidDataException("Audio file metadata has no sender."));
        var address = (client.Client.RemoteEndPoint as IPEndPoint)?.Address ?? throw new IOException("Audio file peer address is unavailable.");
        Ticket ticket; lock (_gate) ticket = _current ?? throw new InvalidOperationException("No approved original-file offer exists.");
        try { await ticket.ReceiveAsync(session, network, metadata, address, token).ConfigureAwait(false); }
        catch (AudioOriginalFileCleanupException error) { throw new LanIncomingPeerCleanupException(ticket, error); }
    }

    internal sealed class Ticket
    {
        private readonly AudioOriginalFileReceiveRegistry _registry;
        private readonly LanProductControlListener _listener;
        private readonly AudioOriginalFileAdmission _admission;
        private readonly string _directory;
        private readonly object _gate = new();
        private readonly CancellationTokenSource _stop = new();
        private readonly TaskCompletionSource<AudioOriginalFileArtifact> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task? _receiving, _closing;
        private AudioOriginalFileArtifact? _artifact;
        private AudioOriginalFileCleanupException? _unreleased;
        private bool _closed, _stopDisposed;
        private int _waited;
        internal bool ReleaseConfirmed { get; private set; }
        internal bool ReceiveCancelled { get; private set; }
        internal bool HasStarted { get { lock (_gate) return _receiving is not null; } }
        internal Ticket(AudioOriginalFileReceiveRegistry registry, LanProductControlListener listener,
            AudioOriginalFileAdmission admission, string directory)
        { _registry = registry; _listener = listener; _admission = admission; _directory = directory; }
        internal Task<AudioOriginalFileArtifact> WaitForArtifactAsync()
        {
            if (Interlocked.Exchange(ref _waited, 1) != 0) throw new InvalidOperationException("This original file already has a playback consumer.");
            return _ready.Task;
        }
        internal void RequireCurrent()
        {
            _stop.Token.ThrowIfCancellationRequested();
            _registry.RequireCurrent(this, _listener); _admission.RequireCurrent();
        }
        internal Task ReceiveAsync(LanProductControlSession session, Stream network, ClassicFileMetadata metadata,
            IPAddress address, CancellationToken token)
        {
            RequireCurrent();
            if (!ReferenceEquals(session, _admission.Session)) throw new InvalidDataException("The file came from a different MAIN owner.");
            // Invalid metadata cannot poison the pending approved offer.
            _admission.ValidateIncomingMetadata(metadata, address);
            lock (_gate)
            {
                if (_closed || _receiving is not null) throw new InvalidOperationException("This original-file producer is already claimed or closed.");
                return _receiving = ReceiveCoreAsync(network, metadata, address, token);
            }
        }
        private async Task ReceiveCoreAsync(Stream network, ClassicFileMetadata metadata, IPAddress address, CancellationToken token)
        {
            await Task.Yield();
            using var scope = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token);
            try
            {
                RequireCurrent();
                _artifact = await _admission.ReceiveAsync(network, metadata, address, _directory, scope.Token).ConfigureAwait(false);
                RequireCurrent(); _ready.TrySetResult(_artifact);
            }
            catch (Exception error)
            {
                if (error is AudioOriginalFileCleanupException cleanup) _unreleased = cleanup;
                _ready.TrySetException(error); throw;
            }
        }
        internal void Cancel()
        {
            lock (_gate)
            {
                // Unbind may retain this ticket just before Close removes it.
                // Synchronize cancellation with CTS disposal; a released owner is inert.
                if (_stopDisposed) return;
                _stop.Cancel(); _ready.TrySetCanceled(_stop.Token);
            }
        }
        internal Task CloseAsync()
        {
            lock (_gate) { _closed = true; return _closing ??= CloseCoreAsync(); }
        }
        private async Task CloseCoreAsync()
        {
            await Task.Yield();
            var failures = new List<Exception>();
            try { Cancel(); } catch (Exception error) { failures.Add(error); }
            Task? receiving; lock (_gate) receiving = _receiving;
            if (receiving is not null)
            {
                try { await receiving.ConfigureAwait(false); }
                catch (OperationCanceledException error) when (error.InnerException is null && _stop.IsCancellationRequested)
                { ReceiveCancelled = true; }
                catch (Exception error) { failures.Add(error); }
            }
            if (_unreleased is not null && !failures.Contains(_unreleased)) failures.Add(_unreleased);
            if (_artifact is not null)
                try { await _artifact.DisposeAsync().ConfigureAwait(false); }
                catch (Exception error) { failures.Add(error); }
            ReleaseConfirmed = _unreleased is null && (_artifact is null || _artifact.IsReleased);
            if (ReleaseConfirmed)
            {
                lock (_gate) { _stop.Dispose(); _stopDisposed = true; }
                _registry.Remove(this);
            }
            if (failures.Count == 1) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failures[0]).Throw();
            if (failures.Count > 1) throw new AggregateException("Original-file reception and cleanup reported failures.", failures);
        }
    }
}
