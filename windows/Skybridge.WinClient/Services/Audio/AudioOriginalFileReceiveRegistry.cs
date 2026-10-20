using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.FileTransfer;

namespace Skybridge.WinClient.Services.Audio;

internal enum AudioOriginalFileReceiveSupport { Unavailable, Wave, WaveAndFlac }

/// <summary>One approved playback offer owns its actual classic producer and file.
/// The shared audio host serializes playback; this registry never grants ordinary
/// file writes or infers authority from a transfer ID alone.</summary>
internal sealed class AudioOriginalFileReceiveRegistry
{
    private readonly object _gate = new();
    private NetworkBinding? _binding;
    private readonly Dictionary<LanProductControlSession, UsbRegistration> _usb = [];
    private Ticket? _current;
    internal abstract class Binding(string directory)
    { internal string Directory { get; } = directory; }
    internal sealed class NetworkBinding(LanProductControlListener listener, ushort port, string directory) : Binding(directory)
    {
        internal LanProductControlListener Listener { get; } = listener;
        internal ushort Port { get; } = port;
    }
    internal sealed class UsbRegistration(AudioOriginalFileReceiveRegistry registry, LanProductControlSession session,
        UsbControlRoute route, UsbMuxConnector connector, string directory) : Binding(directory)
    {
        internal LanProductControlSession Session { get; } = session;
        internal UsbControlRoute Route { get; } = route;
        internal UsbMuxConnector Connector { get; } = connector;
        internal bool Retired { get; set; } // Accessed only under the registry gate.
        internal bool IsCurrentFor(LanProductControlSession owner) => registry.IsCurrentUsb(this, owner);
        internal void RequireCurrentFor(LanProductControlSession owner)
        {
            if (!IsCurrentFor(owner)) throw new InvalidOperationException("The exact USB file receiver is unavailable.");
        }
    }

    internal void Bind(LanProductControlListener listener, string privateDirectory)
    {
        var endpoint = (IPEndPoint)listener.RequireLiveListener().LocalEndpoint;
        var directory = ClassicFileTransferReceiver.ValidateReceiveDirectory(privateDirectory);
        lock (_gate)
        {
            if (_binding is not null || _current?.CarrierBinding is NetworkBinding)
                throw new InvalidOperationException("An original-file listener or artifact is still owned.");
            _binding = new(listener, checked((ushort)endpoint.Port), directory);
        }
    }
    internal UsbRegistration BindUsb(LanProductControlSession session, UsbMuxConnector connector, string privateDirectory)
    {
        ArgumentNullException.ThrowIfNull(session); ArgumentNullException.ThrowIfNull(connector);
        if (session.Carrier is not ProductControlCarrier.Usb usb || !session.IsReady)
            throw new InvalidOperationException("USB file reception requires an admitted USB MAIN owner.");
        _ = session.RequireAudioIdentityBinding();
        var directory = ClassicFileTransferReceiver.ValidateReceiveDirectory(privateDirectory);
        lock (_gate)
        {
            if (_usb.ContainsKey(session) || _usb.Count >= 8)
                throw new InvalidOperationException("The USB file receiver is already installed or at capacity.");
            var binding = new UsbRegistration(this, session, usb.Route, connector, directory);
            _usb.Add(session, binding); return binding;
        }
    }
    private bool IsCurrentUsb(UsbRegistration binding, LanProductControlSession session)
    {
        lock (_gate) return ReferenceEquals(binding.Session, session) && !binding.Retired && session.IsReady &&
            _usb.TryGetValue(session, out var installed) && ReferenceEquals(installed, binding);
    }
    internal UsbRegistration? UsbReceiverFor(LanProductControlSession session)
    {
        lock (_gate) return _usb.TryGetValue(session, out var binding) && IsCurrentUsb(binding, session) ? binding : null;
    }
    internal async Task UnbindUsbAsync(LanProductControlSession session)
    {
        UsbRegistration binding; Ticket? ticket;
        lock (_gate)
        {
            if (!_usb.TryGetValue(session, out var found)) return;
            binding = found; binding.Retired = true;
            ticket = ReferenceEquals(_current?.CarrierBinding, binding) ? _current : null;
        }
        Exception? failure = null;
        try { if (ticket is not null) await ticket.CloseAsync().ConfigureAwait(false); }
        catch (Exception error) { failure = error; }
        if (ticket is null || ticket.ReleaseConfirmed)
        {
            lock (_gate)
                if (_usb.TryGetValue(session, out var current) && ReferenceEquals(current, binding)) _usb.Remove(session);
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
    internal bool CanReceiveFor(LanProductControlSession session)
    {
        lock (_gate) return session.IsReady && (session.Carrier is ProductControlCarrier.Network &&
            _binding is { } binding && binding.Listener.IsListening && session.LocalFileTransferPort == binding.Port ||
            _usb.TryGetValue(session, out var usb) && IsCurrentUsb(usb, session));
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
            ticket = ReferenceEquals(_current?.CarrierBinding, _binding) ? _current : null;
            _binding = null;
        }
        ticket?.Cancel();
    }
    internal Ticket Register(AudioOriginalFileAdmission admission)
    {
        admission.RequireCurrent();
        lock (_gate)
        {
            Binding binding = admission.Session.Carrier switch
            {
                ProductControlCarrier.Network when _binding is { } network && network.Listener.IsListening &&
                    admission.Session.LocalFileTransferPort == network.Port => network,
                ProductControlCarrier.Usb when _usb.TryGetValue(admission.Session, out var usb) && IsCurrentUsb(usb, admission.Session) => usb,
                _ => throw new InvalidOperationException("The exact MAIN file endpoint is unavailable.")
            };
            if (_current is not null) throw new InvalidOperationException("Another file playback owner has not released its resources.");
            return _current = new(this, binding, admission);
        }
    }
    private void RequireCurrent(Ticket ticket, Binding binding)
    {
        lock (_gate)
            if (!ReferenceEquals(_current, ticket) || !(binding switch
                {
                    NetworkBinding network => ReferenceEquals(_binding, network) && network.Listener.IsListening,
                    UsbRegistration usb => IsCurrentUsb(usb, usb.Session),
                    _ => false
                }))
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
        internal Binding CarrierBinding { get; }
        private readonly AudioOriginalFileAdmission _admission;
        private readonly string _directory;
        private readonly object _gate = new();
        private readonly CancellationTokenSource _stop = new();
        private readonly TaskCompletionSource<AudioOriginalFileArtifact> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task? _receiving, _closing;
        private AudioOriginalFileArtifact? _artifact;
        private Exception? _unreleased;
        private Stream? _returnStream;
        private bool _closed, _stopDisposed;
        private int _waited;
        internal bool ReleaseConfirmed { get; private set; }
        internal bool ReceiveCancelled { get; private set; }
        internal bool HasStarted { get { lock (_gate) return _receiving is not null; } }
        internal bool UsesUsbReturn => CarrierBinding is UsbRegistration;
        internal Ticket(AudioOriginalFileReceiveRegistry registry, Binding binding, AudioOriginalFileAdmission admission)
        { _registry = registry; CarrierBinding = binding; _admission = admission; _directory = binding.Directory; }
        internal Task<AudioOriginalFileArtifact> WaitForArtifactAsync()
        {
            if (Interlocked.Exchange(ref _waited, 1) != 0) throw new InvalidOperationException("This original file already has a playback consumer.");
            return _ready.Task;
        }
        internal void RequireCurrent()
        {
            _stop.Token.ThrowIfCancellationRequested();
            _registry.RequireCurrent(this, CarrierBinding); _admission.RequireCurrent();
        }
        internal Task ReceiveAsync(LanProductControlSession session, Stream network, ClassicFileMetadata metadata,
            IPAddress address, CancellationToken token)
        {
            RequireCurrent();
            if (CarrierBinding is not NetworkBinding) throw new InvalidDataException("A network connection cannot claim a USB file offer.");
            if (!ReferenceEquals(session, _admission.Session)) throw new InvalidDataException("The file came from a different MAIN owner.");
            // Invalid metadata cannot poison the pending approved offer.
            _admission.ValidateIncomingMetadata(metadata, address);
            lock (_gate)
            {
                if (_closed || _receiving is not null) throw new InvalidOperationException("This original-file producer is already claimed or closed.");
                return _receiving = ReceiveCoreAsync(network, metadata, address, token);
            }
        }
        // Called only after the exact audio offer has been accepted. The ticket
        // claims one port and owns the actual mux stream through cancellation.
        internal void StartUsbReturn(ushort port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); RequireCurrent(); _admission.RequireEffectCurrent();
            if (port == 0 || CarrierBinding is not UsbRegistration usb)
                throw new InvalidDataException("This file offer has no admitted USB return route.");
            lock (_gate)
            {
                if (_closed || _receiving is not null) throw new InvalidOperationException("The USB file return was already claimed or closed.");
                _receiving = ReceiveUsbCoreAsync(usb, port, token);
            }
        }
        private async Task ReceiveUsbCoreAsync(UsbRegistration usb, ushort port, CancellationToken token)
        {
            await Task.Yield();
            using var scope = CancellationTokenSource.CreateLinkedTokenSource(token, _stop.Token, usb.Session.Lifetime);
            Exception? failure = null;
            try
            {
                RequireCurrent(); _admission.RequireEffectCurrent();
                _returnStream = await usb.Connector.OpenAsync(usb.Route.Udid, port, scope.Token).ConfigureAwait(false);
                RequireCurrent(); _admission.RequireEffectCurrent();
                var first = await ClassicFileTransferOperation.ReadAsync(_returnStream, TimeSpan.FromSeconds(5), scope.Token).ConfigureAwait(false);
                RequireCurrent(); _admission.RequireEffectCurrent();
                if (first.Type != ClassicFileFrameType.Metadata) throw new InvalidDataException("A USB audio file return must start with metadata.");
                var metadata = ClassicFileTransferWire.Decode<ClassicFileMetadata>(first.Payload);
                _admission.ValidateIncomingUsbMetadata(metadata, usb.Route);
                _artifact = await _admission.ReceiveUsbAsync(_returnStream, metadata, usb.Route, _directory, scope.Token).ConfigureAwait(false);
                RequireCurrent();
            }
            catch (Exception error)
            {
                failure = error;
                if (HasUnreleasedOwner(error)) _unreleased = error;
            }
            try
            {
                if (_returnStream is { } stream)
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                    _returnStream = null;
                }
            }
            catch (Exception cleanup)
            {
                _unreleased = new UsbMuxReleaseException(_returnStream ?? throw new InvalidOperationException("USB return owner was lost.", cleanup),
                    failure is null ? cleanup : new AggregateException(failure, cleanup));
                failure = _unreleased;
            }
            if (failure is null)
            {
                try
                {
                    scope.Token.ThrowIfCancellationRequested(); RequireCurrent();
                    if (_artifact is null) throw new InvalidOperationException("USB return produced no verified artifact.");
                }
                catch (Exception error) { failure = error; }
            }
            if (failure is not null)
            {
                _ready.TrySetException(failure); ExceptionDispatchInfo.Capture(failure).Throw();
            }
            _ready.TrySetResult(_artifact!);
        }
        private static bool HasUnreleasedOwner(Exception error) => error is UsbMuxReleaseException or AudioOriginalFileCleanupException ||
            error is AggregateException aggregate && aggregate.InnerExceptions.Any(HasUnreleasedOwner) ||
            error.InnerException is { } inner && HasUnreleasedOwner(inner);
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
            ReleaseConfirmed = _unreleased is null && _returnStream is null && (_artifact is null || _artifact.IsReleased);
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
