namespace Skybridge.WinClient.Services.Audio;

internal enum LanAudioReceiveDisposition { Unavailable, Queued, Retired, QueueOverflow, DeclinedOffer }

internal interface ILanAudioStreamInbox : IDisposable
{
    Guid StreamId { get; }
    AudioSessionIdentityBinding Binding { get; }
    AudioPlaybackSource Source { get; }
    void RequireCurrent();
    // Bounded atomic liveness check for writer/native admission; no carrier/cache locks.
    void RequireEffectCurrent();
    Task<AudioStreamingMessage> ReadAsync(CancellationToken cancellationToken);
}

internal interface ILanAudioSendLease : IDisposable
{
    T Admit<T>(Func<T> prepareFrame);
    void RequireCurrent();
}

internal sealed class LanAudioStreamException(AudioStreamingStopReason reason, string message) : IOException(message)
{
    internal AudioStreamingStopReason Reason { get; } = reason;
}

/// <summary>Bounded receiving side of one MAIN owner. Opening an inbox permits inspection of
/// an offer only; account authorization, consent, replies and output belong to the audio service.</summary>
internal sealed class LanAudioReceiver : IDisposable
{
    internal const int MessageCapacity = 8;
    internal const int RetiredStreamCapacity = 64;
    private readonly object _gate = new();
    private readonly Func<bool> _isReady;
    private readonly TimeSpan _offerTimeout;
    private readonly CancellationTokenRegistration _lifetimeRegistration;
    private readonly HashSet<Guid> _retired = [];
    private OfferWaiter? _waiting;
    private StreamInbox? _active;
    private volatile bool _closed;
    private volatile bool _identityInvalidated;
    private bool _declineUnattendedOffers;

    internal LanAudioReceiver(Func<bool> isReady, CancellationToken lifetime, TimeSpan? offerTimeout = null)
    {
        _isReady = isReady ?? throw new ArgumentNullException(nameof(isReady));
        _offerTimeout = offerTimeout ?? TimeSpan.FromSeconds(30);
        if (_offerTimeout <= TimeSpan.Zero || _offerTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(offerTimeout));
        _lifetimeRegistration = lifetime.Register(Close);
    }

    internal async Task<ILanAudioStreamInbox> AcceptOfferAsync(AudioSessionIdentityBinding binding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        cancellationToken.ThrowIfCancellationRequested();
        OfferWaiter waiting;
        lock (_gate)
        {
            RequireLive();
            if (_active is not null || _waiting is not null)
                throw new InvalidOperationException("Only one audio stream or pending offer is allowed per MAIN session.");
            if (_retired.Count >= RetiredStreamCapacity)
                throw new InvalidOperationException("This MAIN session has reached its retired audio stream limit.");
            waiting = new(binding);
            _waiting = waiting;
        }
        var delivered = false;
        var failureReason = AudioStreamingStopReason.ReceiverDeclined;
        try
        {
            var inbox = await waiting.Completion.Task.WaitAsync(_offerTimeout, cancellationToken).ConfigureAwait(false);
            lock (_gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                RequireCurrent(inbox);
                delivered = true;
                return inbox;
            }
        }
        catch (TimeoutException) { failureReason = AudioStreamingStopReason.TimedOut; throw; }
        finally
        {
            if (!delivered)
            {
                lock (_gate)
                {
                    if (ReferenceEquals(_waiting, waiting)) _waiting = null;
                    if (waiting.Inbox is { } inbox && ReferenceEquals(_active, inbox))
                        Retire(inbox, failureReason, "Audio offer acceptance ended before delivery.");
                }
            }
        }
    }

    // Called by the unique MAIN reader after full wire validation. Never waits for consumer capacity.
    internal LanAudioReceiveDisposition Receive(AudioStreamingMessage message)
    {
        lock (_gate)
        {
            if (_closed) throw Ended();
            if (_retired.Contains(message.StreamId)) return LanAudioReceiveDisposition.Retired;
            if (_identityInvalidated || !_isReady()) return LanAudioReceiveDisposition.Unavailable;
            if (_active is null)
            {
                if (_waiting is null || message.Body is not (AudioStreamingBody.FileOffer or AudioStreamingBody.CaptureOffer))
                {
                    if (_waiting is null && _declineUnattendedOffers && message.Body is AudioStreamingBody.FileOffer or AudioStreamingBody.CaptureOffer)
                    {
                        if (_retired.Count >= RetiredStreamCapacity)
                            throw new InvalidDataException("The MAIN session exhausted its audio stream retirement capacity.");
                        _retired.Add(message.StreamId);
                        return LanAudioReceiveDisposition.DeclinedOffer;
                    }
                    return LanAudioReceiveDisposition.Unavailable;
                }
                var waiting = _waiting;
                var inbox = new StreamInbox(this, message.StreamId, waiting.Binding, AudioPlaybackSource.FromOffer(message));
                inbox.Messages.Enqueue(message); // First offer is visible before the inbox is published.
                _active = inbox;
                waiting.Inbox = inbox;
                _waiting = null;
                waiting.Completion.TrySetResult(inbox);
                return LanAudioReceiveDisposition.Queued;
            }
            if (_active.StreamId != message.StreamId)
                throw new InvalidDataException("Audio message belongs to a different active stream.");
            // Stop is terminal even while the consumer is awaiting local approval or
            // native preparation. Do not leave permission live behind buffered PCM.
            if (message.Body is AudioStreamingBody.Stop stop)
            {
                Retire(_active, stop.Reason, "The peer stopped this audio stream.");
                return LanAudioReceiveDisposition.Retired;
            }
            if (_active.InputEnded)
            {
                Retire(_active, AudioStreamingStopReason.ProtocolViolation, "The peer sent more audio input after End.");
                return LanAudioReceiveDisposition.Retired;
            }
            if (_active.Messages.Count >= MessageCapacity)
            {
                Retire(_active, AudioStreamingStopReason.QueueOverflow, "Audio receiver queue exceeded its bounded capacity.");
                return LanAudioReceiveDisposition.QueueOverflow;
            }
            _active.Messages.Enqueue(message);
            if (message.Body is AudioStreamingBody.End) _active.InputEnded = true;
            _active.Changed.TrySetResult();
            _active.Changed = NewSignal();
            return LanAudioReceiveDisposition.Queued;
        }
    }

    private async Task<AudioStreamingMessage> ReadAsync(StreamInbox inbox, CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref inbox.Reading, 1, 0) != 0)
            throw new InvalidOperationException("An audio inbox permits one pending read.");
        try
        {
            while (true)
            {
                Task changed;
                lock (_gate)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    RequireCurrent(inbox);
                    if (inbox.Messages.TryDequeue(out var message)) return message;
                    changed = inbox.Changed.Task;
                }
                await changed.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally { Volatile.Write(ref inbox.Reading, 0); }
    }

    internal ILanAudioSendLease BeginSend(ILanAudioStreamInbox handle, Guid streamId)
    {
        lock (_gate)
        {
            if (handle is not StreamInbox inbox || !ReferenceEquals(inbox.Owner, this))
                throw new InvalidDataException("Audio reply belongs to a different MAIN owner.");
            RequireCurrent(inbox);
            if (streamId != inbox.StreamId)
                throw new InvalidDataException("Audio reply belongs to a different stream.");
            if (inbox.PendingSend is not null)
                throw new InvalidOperationException("Only one pending audio reply is allowed per stream.");
            var lease = new SendLease(this, inbox);
            inbox.PendingSend = lease;
            return lease;
        }
    }

    private void RequireSend(SendLease lease)
    {
        RequireCurrent(lease.Inbox);
        if (!ReferenceEquals(lease.Inbox.PendingSend, lease))
            throw new InvalidOperationException("The audio send lease has ended.");
    }

    private sealed class SendLease(LanAudioReceiver owner, StreamInbox inbox) : ILanAudioSendLease
    {
        internal StreamInbox Inbox { get; } = inbox;
        public T Admit<T>(Func<T> prepareFrame)
        {
            ArgumentNullException.ThrowIfNull(prepareFrame);
            lock (owner._gate)
            {
                owner.RequireSend(this);
                var frame = prepareFrame();
                owner.RequireSend(this);
                return frame;
            }
        }
        public void RequireCurrent() { lock (owner._gate) owner.RequireSend(this); }
        public void Dispose()
        {
            lock (owner._gate)
                if (ReferenceEquals(Inbox.PendingSend, this)) Inbox.PendingSend = null;
        }
    }

    private void RequireCurrent(StreamInbox inbox)
    {
        if (inbox.Failure is { } failure) throw failure;
        RequireLive();
        if (!ReferenceEquals(_active, inbox)) throw Ended();
    }

    private void RequireLive()
    {
        if (_closed || _identityInvalidated || !_isReady()) throw Ended();
    }

    private static LanAudioStreamException Ended() =>
        new(AudioStreamingStopReason.SessionReplaced, "The audio MAIN owner is no longer live and admitted.");

    private void Retire(StreamInbox inbox, AudioStreamingStopReason reason, string message)
    {
        Interlocked.CompareExchange(ref inbox.Failure, new(reason, message), null);
        inbox.Messages.Clear();
        inbox.Changed.TrySetResult();
        if (ReferenceEquals(_active, inbox))
        {
            _retired.Add(inbox.StreamId);
            _active = null;
        }
    }

    private void CloseInbox(StreamInbox inbox)
    {
        lock (_gate) Retire(inbox, AudioStreamingStopReason.UserStopped, "The audio inbox was closed.");
    }

    private void Close()
    {
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;
            RetireCurrent();
        }
    }

    private void RetireCurrent()
    {
        _waiting?.Completion.TrySetException(Ended());
        _waiting = null;
        if (_active is { } inbox) Retire(inbox, AudioStreamingStopReason.SessionReplaced, "The audio identity owner ended.");
    }

    public void Dispose() { Close(); _lifetimeRegistration.Dispose(); }
    internal void InvalidateIdentity()
    {
        lock (_gate)
        {
            if (_identityInvalidated) return;
            _identityInvalidated = true;
            RetireCurrent();
        }
    }
    internal void RequireLiveOwner() { lock (_gate) RequireLive(); }
    internal void RequireOwnedInbox(ILanAudioStreamInbox handle)
    {
        lock (_gate)
        {
            if (handle is not StreamInbox inbox || !ReferenceEquals(inbox.Owner, this))
                throw new InvalidDataException("The audio inbox belongs to another MAIN owner.");
            RequireCurrent(inbox);
        }
    }
    internal void SetConsumerAdvertisement(bool enabled)
    {
        lock (_gate)
        {
            if (enabled)
            {
                RequireLive();
                if (_waiting is null && _active is null)
                    throw new InvalidOperationException("Install an actual audio consumer before advertising reception.");
            }
            _declineUnattendedOffers = enabled;
        }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private sealed class OfferWaiter(AudioSessionIdentityBinding binding)
    {
        internal AudioSessionIdentityBinding Binding { get; } = binding;
        internal TaskCompletionSource<StreamInbox> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal StreamInbox? Inbox;
    }

    private sealed class StreamInbox : ILanAudioStreamInbox
    {
        internal LanAudioReceiver Owner { get; }
        internal readonly Queue<AudioStreamingMessage> Messages = new(MessageCapacity);
        internal TaskCompletionSource Changed = NewSignal();
        internal LanAudioStreamException? Failure;
        internal int Reading;
        internal bool InputEnded;
        internal SendLease? PendingSend;
        internal StreamInbox(LanAudioReceiver owner, Guid streamId, AudioSessionIdentityBinding binding, AudioPlaybackSource source)
        { Owner = owner; StreamId = streamId; Binding = binding; Source = source; }
        public Guid StreamId { get; }
        public AudioSessionIdentityBinding Binding { get; }
        public AudioPlaybackSource Source { get; }
        public void RequireCurrent() { lock (Owner._gate) Owner.RequireCurrent(this); }
        public void RequireEffectCurrent()
        {
            if (Volatile.Read(ref Failure) is { } failure) throw failure;
            // _isReady must be a nonblocking owner-state read (production: IsReady).
            // Every retirement publishes Failure before allowing a replacement inbox.
            Owner.RequireLive();
            if (Volatile.Read(ref Failure) is { } ended) throw ended;
        }
        public Task<AudioStreamingMessage> ReadAsync(CancellationToken cancellationToken) => Owner.ReadAsync(this, cancellationToken);
        public void Dispose() => Owner.CloseInbox(this);
    }
}
