using System.Buffers.Binary;
using System.Net.Sockets;

namespace Skybridge.WinClient.Services;

/// <summary>One ordered framed channel whose reader spans handshake and control phases.</summary>
internal sealed class TcpProductControlTransport : IProductHandshakeTransport, IAsyncDisposable
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly SemaphoreSlim _sendGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _stateGate = new();
    private readonly TaskCompletionSource _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TimeSpan _sendTimeout;
    private readonly int _maximumInboundFrameBytes;
    private readonly int _maximumOutboundFrameBytes;
    private bool _closed;
    private bool _disposed;
    private int _operations;
    private Exception? _terminalFailure;
    private TaskCompletionSource<Exception?>? _activeWriteOutcome;

    public TcpProductControlTransport(TcpClient client, int maximumInboundFrameBytes,
        int maximumOutboundFrameBytes, TimeSpan? sendTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (maximumInboundFrameBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumInboundFrameBytes));
        if (maximumOutboundFrameBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumOutboundFrameBytes));
        _maximumInboundFrameBytes = maximumInboundFrameBytes;
        _maximumOutboundFrameBytes = maximumOutboundFrameBytes;
        _sendTimeout = sendTimeout ?? TimeSpan.FromSeconds(5);
        if (_sendTimeout <= TimeSpan.Zero || _sendTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(sendTimeout));
        _client = client;
        try
        {
            client.NoDelay = true;
            // Static desktops can leave the control channel idle. Bound loss of
            // a vanished peer through TCP liveness without adding protocol traffic.
            client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            client.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 10);
            client.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 3);
            client.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
            _stream = client.GetStream();
        }
        catch
        {
            client.Dispose();
            _sendGate.Dispose();
            _lifetime.Dispose();
            throw;
        }
    }

    public Task<ReadOnlyMemory<byte>> ReadAsync(CancellationToken cancellationToken) =>
        ReadBoundedAsync(_maximumInboundFrameBytes, cancellationToken);

    // A handshake may impose a smaller bound on this same carrier before MAIN
    // takes over its sole reader. Reject the prefix before allocating a body.
    internal async Task<ReadOnlyMemory<byte>> ReadBoundedAsync(int maximumFrameBytes, CancellationToken cancellationToken)
    {
        if (maximumFrameBytes <= 0 || maximumFrameBytes > _maximumInboundFrameBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumFrameBytes));
        using var linked = BeginOperation(cancellationToken);
        try
        {
            var header = new byte[4];
            await _stream.ReadExactlyAsync(header, linked.Token).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (length == 0 || length > maximumFrameBytes)
                throw new InvalidDataException("Remote-control frame length exceeds the inbound limit.");
            var payload = new byte[checked((int)length)];
            await _stream.ReadExactlyAsync(payload, linked.Token).ConfigureAwait(false);
            return payload;
        }
        catch (Exception readFailure) when (readFailure is OperationCanceledException or IOException or ObjectDisposedException &&
            !cancellationToken.IsCancellationRequested)
        {
            if (await ObserveActiveWriteFailureAsync(readFailure, cancellationToken).ConfigureAwait(false) is { } sendFailure)
                throw new AggregateException("Remote-control send failed and its reader was interrupted.", sendFailure, readFailure);
            throw;
        }
        finally { EndOperation(); }
    }

    private async Task<Exception?> ObserveActiveWriteFailureAsync(Exception readFailure, CancellationToken cancellationToken)
    {
        Task<Exception?>? pending;
        lock (_stateGate)
        {
            if (_terminalFailure is { } terminal) return terminal;
            if (_closed) return null;
            pending = _activeWriteOutcome?.Task;
        }
        // Protocol rejection and peer EOF must not wait for an unrelated writer.
        bool nativeInterruption = readFailure is OperationCanceledException or ObjectDisposedException ||
            readFailure is IOException { InnerException: SocketException };
        if (pending is null || !nativeInterruption) return null;

        // On Windows, cancelling an overlapped send can abort the reader before
        // the sender's continuation publishes its timeout. Observe that exact
        // admitted writer, never a queued or later frame. A reader cancellation
        // stops this observation; its original read failure still propagates.
        Exception? outcome;
        try { outcome = await pending.WaitAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return null; }
        return outcome is not null && ReferenceEquals(outcome, Volatile.Read(ref _terminalFailure)) ? outcome : null;
    }

    public async Task SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken)
    {
        if (frame.IsEmpty || frame.Length > _maximumOutboundFrameBytes)
            throw new InvalidDataException("Remote-control frame exceeds the outbound limit.");
        await SendAdmittedAsync(() => frame, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Prepare a frame only after acquiring the shared writer. The callback is synchronous,
    /// bounded and non-reentrant; it must validate feature authority before returning owned bytes.
    /// Rejection before any write preserves the framing boundary and the transport.</summary>
    internal async Task SendAdmittedAsync(Func<ReadOnlyMemory<byte>> prepareFrame, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(prepareFrame);
        using var deadline = BeginOperation(cancellationToken);
        deadline.CancelAfter(_sendTimeout);
        var entered = false;
        var writeStarted = false;
        var inAdmissionCallback = false;
        TaskCompletionSource<Exception?>? writeOutcome = null;
        Exception? writeFailure = null;
        var phase = "waiting for the previous frame";
        ReadOnlyMemory<byte> frame = default;
        try
        {
            await _sendGate.WaitAsync(deadline.Token).ConfigureAwait(false);
            entered = true;
            deadline.Token.ThrowIfCancellationRequested();
            phase = "checking frame admission";
            inAdmissionCallback = true;
            frame = prepareFrame();
            inAdmissionCallback = false;
            if (frame.IsEmpty || frame.Length > _maximumOutboundFrameBytes)
                throw new InvalidDataException("Admitted frame exceeds the outbound limit.");
            deadline.Token.ThrowIfCancellationRequested();
            var header = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(header, checked((uint)frame.Length));
            phase = "writing the frame prefix";
            writeStarted = true;
            writeOutcome = new(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_stateGate) { _activeWriteOutcome = writeOutcome; }
            await _stream.WriteAsync(header, deadline.Token).ConfigureAwait(false);
            phase = "writing the frame body";
            await _stream.WriteAsync(frame, deadline.Token).ConfigureAwait(false);
        }
        // A callback's own cancellation must retain its cause even if the timer expires concurrently.
        catch (OperationCanceledException failure) when (!inAdmissionCallback && deadline.IsCancellationRequested &&
            !cancellationToken.IsCancellationRequested && !_lifetime.IsCancellationRequested)
        {
            var timeout = new TimeoutException(
                $"Remote-control send timed out after {_sendTimeout.TotalSeconds:F1}s while {phase} " +
                $"({(frame.IsEmpty ? "frame not prepared" : $"{frame.Length} bytes")}).", failure);
            writeFailure = timeout;
            if (writeStarted) Close(timeout);
            throw timeout;
        }
        catch (Exception failure)
        {
            writeFailure = failure;
            // Once a prefix or body may have been sent, the framing boundary is
            // uncertain. Retire the exact transport instead of retrying a frame.
            // Cancellation while waiting for the writer has not touched the wire.
            if (writeStarted) Close(failure);
            throw;
        }
        finally
        {
            if (writeOutcome is not null)
            {
                lock (_stateGate)
                {
                    if (ReferenceEquals(_activeWriteOutcome, writeOutcome)) _activeWriteOutcome = null;
                }
                writeOutcome.TrySetResult(writeFailure);
            }
            if (entered) _sendGate.Release();
            EndOperation();
        }
    }

    private CancellationTokenSource BeginOperation(CancellationToken cancellationToken)
    {
        lock (_stateGate)
        {
            if (_closed) throw new IOException("The remote-control transport is closed.");
            var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            _operations++;
            return linked;
        }
    }

    private void EndOperation()
    {
        lock (_stateGate)
        {
            _operations--;
            if (_closed && _operations == 0) _drained.TrySetResult();
        }
    }

    public void Close() => Close(null);

    private void Close(Exception? failure)
    {
        lock (_stateGate)
        {
            if (_closed) return;
            Volatile.Write(ref _terminalFailure, failure);
            _closed = true;
            _lifetime.Cancel();
            _client.Dispose();
            if (_operations == 0) _drained.TrySetResult();
        }
    }

    public async ValueTask DisposeAsync()
    {
        Close();
        await _drained.Task.ConfigureAwait(false);
        lock (_stateGate)
        {
            if (_disposed) return;
            _disposed = true;
            _sendGate.Dispose();
            _lifetime.Dispose();
        }
    }
}
