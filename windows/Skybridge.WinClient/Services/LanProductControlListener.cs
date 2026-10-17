using System.Net;
using System.Net.Sockets;

namespace Skybridge.WinClient.Services;

internal sealed class LanIncomingPeerCleanupException(object retainedOwner, Exception failure)
    : IOException("Incoming MAIN resources were not fully released.", failure)
{
    internal object RetainedOwner { get; } = retainedOwner;
}

internal sealed record LanProductListenerSnapshot(IPEndPoint? Endpoint, int ActiveConnections,
    long RejectedConnections, bool Stopping, bool ReleaseUnconfirmed, Exception? Failure);

/// <summary>One explicit local TCP listener with bounded connection ownership. The
/// peer callback must retain its session until feature teardown actually completes.</summary>
internal sealed class LanProductControlListener(Func<TcpClient, CancellationToken, Task> runPeer,
    Func<bool> isCurrent) : IAsyncDisposable
{
    internal const int MaximumConnections = 8;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _stop = new(1, 1);
    private readonly Dictionary<long, Peer> _peers = [];
    private sealed class Peer(long id, TcpClient client)
    {
        internal readonly long Id = id;
        internal readonly TcpClient Client = client;
        internal readonly TaskCompletionSource Finished = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Exception? Unreleased;
    }
    private CancellationTokenSource? _scope;
    private CancellationTokenRegistration _shutdown;
    private TcpListener? _listener;
    private IPEndPoint? _endpoint;
    private Task _accept = Task.CompletedTask, _authority = Task.CompletedTask;
    private long _nextId, _rejected;
    private bool _started, _stopping, _disposed;
    private Exception? _failure, _terminalFailure;

    // Both network producers end before the workspace's automatic advertisement teardown.
    internal Task NetworkEnded => Task.WhenAll(_accept, _authority);

    internal void Start(IPAddress address, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(runPeer);
        ArgumentNullException.ThrowIfNull(isCurrent);
        // The workspace separately revalidates the explicitly selected OS interface.
        if (address.AddressFamily != AddressFamily.InterNetwork || address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.Broadcast) || address.GetAddressBytes()[0] >= 224)
            throw new InvalidDataException("MAIN reception requires one concrete IPv4 interface address.");
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_started) throw new InvalidOperationException("This MAIN listener already owns a start attempt.");
            token.ThrowIfCancellationRequested();
            if (!isCurrent()) throw new InvalidOperationException("The captured account session has ended.");
            _started = true;
            _scope = CancellationTokenSource.CreateLinkedTokenSource(token);
            _listener = new TcpListener(address, 0);
            try
            {
                _listener.Start(MaximumConnections);
                _endpoint = (IPEndPoint)_listener.LocalEndpoint;
                _shutdown = _scope.Token.Register(CloseSockets);
                _accept = AcceptAsync(_listener, _scope.Token);
                _authority = ObserveAuthorityAsync(_scope.Token);
            }
            catch
            {
                _listener.Stop(); _listener = null; _endpoint = null;
                _shutdown.Dispose(); _scope.Dispose(); _scope = null;
                throw;
            }
        }
    }

    internal TcpListener RequireLiveListener()
    {
        lock (_gate)
        {
            if (_listener is null || _scope is null || _scope.IsCancellationRequested || _stopping || _disposed || !isCurrent())
                throw new InvalidOperationException("The MAIN listener is not live.");
            return _listener;
        }
    }
    internal bool IsListening
    {
        get { lock (_gate) return _listener is not null && _scope is { IsCancellationRequested: false } && !_stopping && !_disposed && isCurrent(); }
    }
    internal LanProductListenerSnapshot ReadSnapshot()
    {
        lock (_gate) return new(_endpoint is null || _scope?.IsCancellationRequested != false ? null :
            new IPEndPoint(_endpoint.Address, _endpoint.Port), _peers.Count, _rejected, _stopping,
            _peers.Values.Any(p => p.Unreleased is not null), _failure);
    }
    private void CloseSockets()
    {
        lock (_gate)
        {
            _listener?.Stop();
            foreach (var peer in _peers.Values) peer.Client.Dispose();
        }
    }
    private async Task ObserveAuthorityAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        try
        {
            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
                if (!isCurrent()) { _scope!.Cancel(); return; }
        }
        catch (OperationCanceledException error) when (error.InnerException is null && token.IsCancellationRequested && error.CancellationToken == token) { }
        catch (Exception failure)
        {
            lock (_gate) _terminalFailure = _failure = failure;
            CancelScope();
        }
    }
    private async Task AcceptAsync(TcpListener listener, CancellationToken token)
    {
        try
        {
            while (true)
            {
                var client = await listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                Peer? peer = null;
                try
                {
                    lock (_gate)
                    {
                        if (!token.IsCancellationRequested && isCurrent() && _peers.Count < MaximumConnections)
                        {
                            peer = new(checked(++_nextId), client); _peers.Add(peer.Id, peer);
                        }
                        else _rejected++;
                    }
                }
                finally { if (peer is null) client.Dispose(); }
                if (peer is not null) _ = Task.Run(() => RunPeerAsync(peer, token));
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (SocketException) when (token.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (token.IsCancellationRequested) { }
        catch (Exception failure)
        {
            lock (_gate) _terminalFailure = _failure = failure;
            CancelScope();
        }
    }
    private async Task RunPeerAsync(Peer peer, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            if (!isCurrent()) throw new InvalidOperationException("The captured account session has ended.");
            await runPeer(peer.Client, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error) when (error.InnerException is null && token.IsCancellationRequested && error.CancellationToken == token) { }
        catch (Exception failure)
        {
            lock (_gate)
            {
                _failure = failure;
                if (HasUnreleasedOwner(failure)) peer.Unreleased = failure;
            }
            if (peer.Unreleased is not null) CancelScope();
        }
        finally
        {
            peer.Client.Dispose();
            lock (_gate)
            {
                if (peer.Unreleased is null) _peers.Remove(peer.Id);
                peer.Finished.TrySetResult();
            }
        }
    }
    private static bool HasUnreleasedOwner(Exception error) => error is LanIncomingPeerCleanupException or LanResponderCryptoReleaseException ||
        error is AggregateException aggregate && aggregate.InnerExceptions.Any(HasUnreleasedOwner) ||
        error.InnerException is not null && HasUnreleasedOwner(error.InnerException);

    private void CancelScope()
    {
        try { _scope!.Cancel(); }
        catch (Exception error)
        {
            lock (_gate) _terminalFailure = _failure = _terminalFailure is null ? error : new AggregateException(_terminalFailure, error);
            CloseSockets();
        }
    }

    internal async Task StopAsync()
    {
        await _stop.WaitAsync().ConfigureAwait(false);
        try
        {
            CancellationTokenSource? scope;
            lock (_gate) { scope = _scope; _stopping = scope is not null; }
            if (scope is null) return;
            var failures = new List<Exception>();
            try { scope.Cancel(); } catch (Exception error) { failures.Add(error); CloseSockets(); }
            try { await Task.WhenAll(_accept, _authority).ConfigureAwait(false); } catch (Exception error) { failures.Add(error); }
            Task[] workers; lock (_gate) workers = _peers.Values.Select(p => p.Finished.Task).ToArray();
            await Task.WhenAll(workers).ConfigureAwait(false);
            lock (_gate)
            {
                failures.AddRange(_peers.Values.Where(p => p.Unreleased is not null).Select(p => p.Unreleased!));
                if (_terminalFailure is not null) failures.Add(_terminalFailure);
            }
            bool unreleased; lock (_gate) unreleased = _peers.Values.Any(p => p.Unreleased is not null);
            if (unreleased) throw new AggregateException("MAIN listener shutdown did not fully succeed.", failures);
            _shutdown.Dispose(); scope.Dispose();
            lock (_gate) { _scope = null; _listener = null; _endpoint = null; _stopping = false; }
            if (failures.Count != 0) throw new AggregateException("MAIN listener ended with a failure.", failures);
        }
        finally { _stop.Release(); }
    }
    internal async Task StopWithPublicationAsync(Func<Task> withdrawPublication)
    {
        ArgumentNullException.ThrowIfNull(withdrawPublication);
        // Close acceptance immediately, but do not keep advertising a dead socket
        // while a peer's native teardown is still running. Own both completions.
        var stop = Observe(StopAsync);
        var withdrawal = Observe(withdrawPublication);
        var failures = (await Task.WhenAll(stop, withdrawal).ConfigureAwait(false)).OfType<Exception>().ToArray();
        if (failures.Length != 0) throw new AggregateException("MAIN stop or publication withdrawal failed.", failures);
        static async Task<Exception?> Observe(Func<Task> operation)
        {
            try { await operation().ConfigureAwait(false); return null; }
            catch (Exception error) { return error; }
        }
    }
    public async ValueTask DisposeAsync()
    {
        lock (_gate) _disposed = true;
        await StopAsync().ConfigureAwait(false);
    }
}
