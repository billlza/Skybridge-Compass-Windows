using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

using Skybridge.WinClient.Services.RemoteControl;

namespace Skybridge.WinClient.Services;

internal sealed class RemoteControlHostGenerationMismatchException()
    : InvalidOperationException("The remote-control host generation changed.");

/// <summary>Application owner of the existing device identity and native feature sessions.</summary>
[SupportedOSPlatform("windows10.0.19041")]
internal sealed class WindowsDeviceWorkspace : IAsyncDisposable
{
    private readonly string _stateDirectory;
    private readonly string _displayName;
    private readonly SemaphoreSlim _operations = new(1, 1);
    private readonly SemaphoreSlim _controlOperations = new(1, 1);
    private readonly SemaphoreSlim _mainOperations = new(1, 1);
    private readonly Dictionary<string, LanProductControlSession> _controlSessions = new(StringComparer.Ordinal);
    private readonly object _stateGate = new();
    private RemoteControlIdentityStore? _identity;
    private WindowsRemoteControlHost? _host;
    private Action<WindowsRemoteControlHostStatus>? _hostStatusHandler;
    private CancellationTokenSource? _hostCancellation;
    private Task _hostObservation = Task.CompletedTask;
    private long _generation;
    private volatile bool _disposed;
    private Audio.AudioReceiveHost? _audioReceiveHost;
    private LanProductControlListener? _mainListener;
    private RemoteControlNetworkInterface? _mainNetwork;
    private LanProductControlListener? _audioFileListener;
    internal Audio.AudioOriginalFileReceiveRegistry OriginalAudioFiles { get; } = new();
    private WindowsRemoteControlAdvertisement? _mainAdvertisement;
    private Task<Exception?> _mainObservation = Task.FromResult<Exception?>(null);
    private bool _mainStarting;

    internal bool HasIncomingMain { get { lock (_stateGate) return _mainStarting || _mainListener is not null || _audioFileListener is not null; } }
    internal LanProductListenerSnapshot? ReadIncomingMain()
    {
        lock (_stateGate)
        {
            var state = _mainListener?.ReadSnapshot();
            return state is not null && _mainObservation.IsCompletedSuccessfully && _mainObservation.Result is { } error
                ? state with { Failure = error } : state;
        }
    }

    internal async Task<LanConnectionInfoPublication> PrepareIncomingMainConnectionInfoAsync(CancellationToken token)
    {
        LanProductControlListener listener;
        RemoteControlIdentityStore identity;
        RemoteControlNetworkInterface network;
        lock (_stateGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            listener = _mainListener ?? throw new InvalidOperationException("Enable reception before sharing connection information.");
            identity = _identity ?? throw new InvalidOperationException("The local device identity is unavailable.");
            network = _mainNetwork ?? throw new InvalidOperationException("The listening network is unavailable.");
        }
        var currentNetworks = await OperatorNetworkInterfacesAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        WindowsLanConnectionInfo.RequireCurrentRoute(network, currentNetworks);
        lock (_stateGate)
        {
            return new(identity.PublicMaterial, () =>
            {
                lock (_stateGate)
                {
                    ObjectDisposedException.ThrowIf(_disposed, this);
                    if (_mainStarting || !ReferenceEquals(listener, _mainListener) || !ReferenceEquals(identity, _identity) ||
                        !ReferenceEquals(network, _mainNetwork))
                        throw new InvalidOperationException("The MAIN listener owner changed.");
                    return (IPEndPoint)listener.RequireLiveListener().LocalEndpoint;
                }
            });
        }
    }

    internal async Task StartIncomingMainAsync(RemoteControlNetworkInterface selected,
        RemoteControlViewerAccount account, Audio.AccountAudioAuthorization authorization,
        ILanPibApprovalPresenter pairingApproval, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(selected); ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(pairingApproval);
        await _mainOperations.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this); authorization.RequireCurrent();
            if (_mainListener is not null || _audioFileListener is not null) throw new InvalidOperationException("Stop the current audio listeners before starting another.");
            lock (_stateGate) _mainStarting = true;
            RemoteControlIdentityStore identity;
            await _operations.WaitAsync(token).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _identity ??= authorization.IsOffline
                    ? await RemoteControlIdentityStore.LoadExistingAsync(_stateDirectory, _displayName, token).ConfigureAwait(false)
                    : await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, token).ConfigureAwait(false);
                identity = _identity;
            }
            finally { _operations.Release(); }
            var networks = await OperatorNetworkInterfacesAsync(token).ConfigureAwait(false);
            if (!networks.Contains(selected)) throw new InvalidOperationException("The selected local network changed. Refresh it before receiving.");
            authorization.RequireCurrent();
            var material = identity.PublicMaterial;
            if (authorization.IsOffline)
                (authorization.Recovery ?? throw new InvalidOperationException("Offline audio recovery is unavailable."))
                    .RequireLocalIdentity(Audio.AudioDeviceIdentity.FromRegistryBinding(new CurrentPathProtocolIdentityBinding(
                        material.DeviceId, CurrentPathProtocolSigningAlgorithm.MLDsa65, material.ProtocolPublicKey.ToArray())));
            var local = new RemoteControlSecurityIdentity(account.AccountDisplayName, account.NebulaId, material.DeviceId, material.DeviceName);
            local.Validate();
            var osVersion = QPeriaptPeerPlatform.LocalVersion();
            var refresh = identity.CreateKemRefreshResponder(authorization.RequireCurrent, osVersion);
            var pairing = identity.CreatePibResponder(pairingApproval, authorization.RequireCurrent);
            var fileListener = new LanProductControlListener((client, cancellation) =>
                OriginalAudioFiles.ReceiveAsync(client, RequireIncomingControlSession, cancellation),
                () => !_disposed && authorization.IsCurrent);
            lock (_stateGate) _audioFileListener = fileListener;
            ushort filePort;
            try
            {
                var privateDirectory = Path.Combine(_stateDirectory, "audio-playback");
                Directory.CreateDirectory(privateDirectory);
                fileListener.Start(selected.Address, token);
                OriginalAudioFiles.Bind(fileListener, privateDirectory);
                filePort = checked((ushort)((IPEndPoint)fileListener.RequireLiveListener().LocalEndpoint).Port);
            }
            catch (Exception startFailure)
            {
                try { await ReleaseIncomingMainAsync().ConfigureAwait(false); }
                catch (Exception cleanup) { throw new AggregateException("Audio file listener start and cleanup failed.", startFailure, cleanup); }
                throw;
            }
            var listener = new LanProductControlListener((client, cancellation) =>
                RunIncomingMainPeerAsync(client, identity, local, material, refresh, pairing, authorization, filePort, cancellation),
                () => !_disposed && authorization.IsCurrent);
            var advertisement = new WindowsRemoteControlAdvertisement();
            lock (_stateGate)
            {
                _mainListener = listener; _mainAdvertisement = advertisement;
                _mainNetwork = selected with { Address = new IPAddress(selected.Address.GetAddressBytes()) };
            }
            try
            {
                listener.Start(selected.Address, token);
                var socket = listener.RequireLiveListener();
                var port = ((IPEndPoint)socket.LocalEndpoint).Port;
                var options = new WindowsRemoteControlAdvertisementOptions(material.DeviceName,
                    WindowsDnsSdAdvertisementBackend.GetLocalHostName(), selected.Address, port, selected.InterfaceIndex,
                    new Dictionary<string, string>(StringComparer.Ordinal) {
                        ["version"] = "2", ["deviceId"] = material.DeviceId, ["pubKeyFP"] = material.ProtocolPublicKeyFingerprint,
                        ["platform"] = "windows", ["osVersion"] = osVersion
                    }, WindowsProductAdvertisementService.MainControl);
                await advertisement.StartAsync(socket, options, token).ConfigureAwait(false);
                authorization.RequireCurrent(); token.ThrowIfCancellationRequested();
                _mainObservation = ObserveIncomingMainEndAsync(listener, fileListener, advertisement);
            }
            catch (Exception startFailure)
            {
                try { await ReleaseIncomingMainAsync().ConfigureAwait(false); }
                catch (Exception cleanup) { throw new AggregateException("MAIN listener start and cleanup failed.", startFailure, cleanup); }
                throw;
            }
        }
        finally
        {
            lock (_stateGate) _mainStarting = false;
            _mainOperations.Release();
        }
    }

    internal async Task StopIncomingMainAsync()
    {
        await _mainOperations.WaitAsync().ConfigureAwait(false);
        try { await ReleaseIncomingMainAsync().ConfigureAwait(false); }
        finally { _mainOperations.Release(); }
    }
    private async Task ReleaseIncomingMainAsync()
    {
        var failures = new List<Exception>();
        Task? fileStop = null;
        var fileListener = _audioFileListener;
        if (fileListener is not null)
        {
            try { OriginalAudioFiles.Unbind(fileListener); } catch (Exception error) { failures.Add(error); }
            fileStop = fileListener.StopAsync(); // Cancel file sockets before awaiting MAIN's playback drain.
        }
        if (_mainListener is { } listener)
        {
            try
            {
                await listener.StopWithPublicationAsync(() => _mainAdvertisement?.DisposeAsync().AsTask() ?? Task.CompletedTask).ConfigureAwait(false);
                await listener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception error) { failures.Add(error); }
        }
        if (fileStop is not null)
        {
            try { await fileStop.ConfigureAwait(false); await fileListener!.DisposeAsync().ConfigureAwait(false); }
            catch (Exception error) { failures.Add(error); }
        }
        var observation = await _mainObservation.ConfigureAwait(false);
        if (observation is not null && !failures.Contains(observation)) failures.Add(observation);
        // An observed operational error is reported once; actual unconfirmed owners
        // still throw from their DisposeAsync on every subsequent cleanup attempt.
        _mainObservation = Task.FromResult<Exception?>(null);
        if (failures.Count != 0) throw new AggregateException("Incoming MAIN could not fully stop.", failures);
        lock (_stateGate) { _mainListener = null; _mainNetwork = null; _audioFileListener = null; _mainAdvertisement = null; }
    }
    private async Task<Exception?> ObserveIncomingMainEndAsync(LanProductControlListener listener, LanProductControlListener fileListener,
        WindowsRemoteControlAdvertisement advertisement)
    {
        await Task.WhenAny(listener.NetworkEnded, fileListener.NetworkEnded).ConfigureAwait(false);
        var errors = new List<Exception>();
        try { OriginalAudioFiles.Unbind(fileListener); } catch (Exception error) { errors.Add(error); }
        var fileStop = fileListener.StopAsync();
        var mainStop = listener.StopWithPublicationAsync(() => advertisement.StopAsync());
        foreach (var stopping in new[] { fileStop, mainStop })
            try { await stopping.ConfigureAwait(false); } catch (Exception error) { errors.Add(error); }
        return errors.Count switch { 0 => null, 1 => errors[0], _ => new AggregateException("Audio listener teardown failed.", errors) };
    }

    private async Task RunIncomingMainPeerAsync(TcpClient client, RemoteControlIdentityStore identity,
        RemoteControlSecurityIdentity local, RemoteControlPairingMaterial material,
        SignedLanKemRefreshResponder refresh, LanPibResponder pairing,
        Audio.AccountAudioAuthorization authorization, ushort filePort, CancellationToken token)
    {
        LanProductControlSession? session = null;
        bool registered = false;
        Exception? failure = null;
        try
        {
            authorization.RequireCurrent();
            var accepted = await LanProductControlResponder.AcceptWithBootstrapAsync(client, local, material,
                () => { authorization.RequireCurrent(); return identity.TrustedPeers; },
                () => { authorization.RequireCurrent(); return identity.CreateCryptoProvider(); }, filePort, token, refresh, pairing,
                advertiseGeneralFiles: false).ConfigureAwait(false);
            if (accepted is LanIncomingControlResult.KemRefreshCompleted or LanIncomingControlResult.PairingExchangeCompleted) return;
            session = accepted is LanIncomingControlResult.Main main ? main.Session
                : throw new InvalidOperationException("Unknown incoming MAIN admission result.");
            await _controlOperations.WaitAsync(token).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this); authorization.RequireCurrent();
                if (!session.IsReady) throw new IOException("Incoming MAIN ended before registration.");
                if (_controlSessions.ContainsKey(session.PeerDeviceId))
                    throw new InvalidOperationException("An existing device owner must disconnect before replacement.");
                if (_controlSessions.Count >= LanProductControlListener.MaximumConnections)
                    throw new InvalidOperationException("Eight device sessions are already open.");
                lock (_stateGate) _controlSessions.Add(session.PeerDeviceId, session);
                registered = true;
                if (_audioReceiveHost is { } audio) await audio.AttachAsync(session, token).ConfigureAwait(false);
            }
            finally { _controlOperations.Release(); }
            var ended = await session.Completion.ConfigureAwait(false);
            if (ended is not null) throw new IOException("Incoming MAIN ended with a peer failure.", ended);
        }
        catch (Exception error) { failure = error; }
        if (session is not null)
        {
            await _controlOperations.WaitAsync().ConfigureAwait(false);
            try
            {
                if (registered && _audioReceiveHost is { } audio)
                {
                    try { await audio.DetachAsync(session).ConfigureAwait(false); }
                    catch (Exception error) when (!audio.OwnsSession(session))
                    {
                        // Detach may report a terminal operation error after actual
                        // release. Preserve it, but do not invent an unreleased owner.
                        failure = failure is null ? error : new AggregateException(failure, error);
                    }
                }
                await session.DisposeAsync().ConfigureAwait(false);
                if (registered) lock (_stateGate)
                    if (_controlSessions.TryGetValue(session.PeerDeviceId, out var current) && ReferenceEquals(current, session))
                        _controlSessions.Remove(session.PeerDeviceId);
            }
            catch (Exception cleanup)
            {
                throw new LanIncomingPeerCleanupException(session, failure is null ? cleanup : new AggregateException(failure, cleanup));
            }
            finally { _controlOperations.Release(); }
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }

    internal void ConfigureAudioReception(Audio.AudioReceiveHost host)
    {
        ArgumentNullException.ThrowIfNull(host);
        lock (_stateGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_audioReceiveHost is not null || _controlSessions.Count != 0)
                throw new InvalidOperationException("Configure audio reception before establishing device sessions.");
            _audioReceiveHost = host;
        }
    }

    public bool HasHost
    {
        get { lock (_stateGate) return _host is not null; }
    }

    public long CurrentGeneration => Interlocked.Read(ref _generation);

    internal (long Generation, bool Enabled, WindowsRemoteControlHostStatus? Status) ReadOperatorHost()
    {
        lock (_stateGate) return (CurrentGeneration, _host is not null, _host?.CurrentStatus);
    }

    internal static Task<IReadOnlyList<RemoteControlNetworkInterface>> OperatorNetworkInterfacesAsync(CancellationToken token)
        => Task.Run(ReadNetworkInterfaces, token);

    internal async Task StopOperatorHostAsync(long expectedGeneration, CancellationToken token)
    {
        await _operations.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (CurrentGeneration != expectedGeneration)
                throw new RemoteControlHostGenerationMismatchException();
            if (_host is { } host)
            {
                lock (_stateGate) _hostCancellation?.Cancel();
                await host.StopAsync().ConfigureAwait(false);
                await ReleaseHostAsync(host).ConfigureAwait(false);
            }
        }
        finally { _operations.Release(); }
    }

    public WindowsDeviceWorkspace()
        : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SkyBridge", "remote-control"), Environment.MachineName)
    {
    }

    internal WindowsDeviceWorkspace(string stateDirectory, string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stateDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        _stateDirectory = stateDirectory;
        _displayName = displayName;
    }

    public event Action<RemoteControlHostWorkspaceStatus>? StatusChanged;

    internal Task<ProductPeerAuthentication> PrepareViewerAuthenticationAsync(DiscoveryBrowserPeerCandidate candidate,
        RemoteControlViewerAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(account);
        var endpoint = candidate.Routes.RemoteDesktop
            ?? throw new InvalidOperationException("The selected device has no resolved remote-desktop route.");
        return PreparePeerAuthenticationAsync(candidate, account, endpoint, cancellationToken);
    }

    internal async Task<Connection.UsbPeerPairingState> InspectUsbPairingAsync(
        Connection.UsbPeerInspection inspection, CancellationToken token)
    {
        await _operations.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_identity is null)
            {
                try { _identity = await RemoteControlIdentityStore.LoadExistingAsync(_stateDirectory, _displayName, token).ConfigureAwait(false); }
                catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
                {
                    // A genuinely new installation has no saved identity. A missing
                    // lock beside an existing identity is a storage failure, not an
                    // unpaired device and never permission to recreate that identity.
                    try { _ = File.GetAttributes(Path.Combine(_stateDirectory, "remote-control-identity.bin")); }
                    catch (Exception absent) when (absent is FileNotFoundException or DirectoryNotFoundException)
                    { return Connection.UsbPeerPairingState.Unpaired; }
                    throw;
                }
            }
            token.ThrowIfCancellationRequested();
            return Connection.UsbPeerPairingMatcher.Match(inspection, _identity.PublicMaterial.DeviceId, _identity.TrustedMaterials);
        }
        finally { _operations.Release(); }
    }

    internal Task<ProductPeerAuthentication> PrepareControlAuthenticationAsync(DiscoveryBrowserPeerCandidate candidate,
        RemoteControlViewerAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(account);
        var endpoint = candidate.Routes.Control
            ?? throw new InvalidOperationException("The selected device has no resolved product-control route.");
        return PreparePeerAuthenticationAsync(candidate, account, endpoint, cancellationToken);
    }

    internal async Task<LanProductControlSession> ConnectControlAsync(DiscoveryBrowserPeerCandidate candidate,
        RemoteControlViewerAccount account, ushort localFileTransferPort, CancellationToken cancellationToken)
    {
        await _controlOperations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var deviceId = RemoteControlHandshakeBinding.CanonicalDeviceId(candidate.Peer.DeviceId);
            foreach (var stale in _controlSessions.Where(entry => !entry.Value.IsReady).ToArray())
            {
                if (_audioReceiveHost is { } audio) await audio.DetachAsync(stale.Value).ConfigureAwait(false);
                await stale.Value.DisposeAsync().ConfigureAwait(false);
                lock (_stateGate) _controlSessions.Remove(stale.Key);
            }
            if (_controlSessions.TryGetValue(deviceId, out var existing))
            {
                // Reuse only if the currently selected identity and both routes still
                // belong to this exact session. Route changes require an explicit disconnect.
                existing.RequireFileTransferRoute(candidate);
                return existing;
            }
            if (_controlSessions.Count >= 8) throw new InvalidOperationException("Eight device sessions are already open. Disconnect before adding another.");
            var authority = await PrepareControlAuthenticationAsync(candidate, account, cancellationToken).ConfigureAwait(false);
            var session = await LanProductControlSession.ConnectAsync(authority, localFileTransferPort, cancellationToken).ConfigureAwait(false);
            lock (_stateGate) _controlSessions.Add(deviceId, session);
            // The registered session remains owned even if feature startup fails;
            // explicit disconnect must drain any actual consumer before removal.
            if (_audioReceiveHost is { } receiver) await receiver.AttachAsync(session, cancellationToken).ConfigureAwait(false);
            return session;
        }
        finally { _controlOperations.Release(); }
    }

    internal LanProductControlSession RequireIncomingControlSession(string deviceId)
    {
        lock (_stateGate)
        {
            if (_disposed || !_controlSessions.TryGetValue(RemoteControlHandshakeBinding.CanonicalDeviceId(deviceId), out var session) || !session.IsReady)
                throw new InvalidDataException("This sender does not have an established device session.");
            return session;
        }
    }

    internal async Task DisconnectControlSessionsAsync()
    {
        await _controlOperations.WaitAsync().ConfigureAwait(false);
        try
        {
            var failures = new List<Exception>();
            foreach (var entry in _controlSessions.ToArray())
            {
                try
                {
                    if (_audioReceiveHost is { } audio) await audio.DetachAsync(entry.Value).ConfigureAwait(false);
                    await entry.Value.DisposeAsync().ConfigureAwait(false);
                    lock (_stateGate) _controlSessions.Remove(entry.Key);
                }
                catch (Exception failure) { failures.Add(failure); }
            }
            if (failures.Count > 0) throw new AggregateException("Device sessions could not be fully released.", failures);
        }
        finally { _controlOperations.Release(); }
    }

    private async Task<ProductPeerAuthentication> PreparePeerAuthenticationAsync(DiscoveryBrowserPeerCandidate candidate,
        RemoteControlViewerAccount account, DiscoveryPeerEndpoint endpoint, CancellationToken cancellationToken)
    {
        WebRtcProductPqcHandshakeCryptoProvider crypto;
        RemoteControlSecurityIdentity localIdentity;
        RemoteControlPairingMaterial localPairing;
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _identity ??= await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, cancellationToken).ConfigureAwait(false);
            localIdentity = new(account.AccountDisplayName, account.NebulaId, _identity.PublicMaterial.DeviceId, _identity.PublicMaterial.DeviceName);
            localIdentity.Validate();
            localPairing = _identity.PublicMaterial;
            crypto = _identity.CreateInitiatorCryptoProvider(candidate.Peer.DeviceId, candidate.Peer.PublicKeyFingerprint);
        }
        finally { _operations.Release(); }
        return new(endpoint, new ProductHandshakePeerContext(RemoteControlHandshakeBinding.CanonicalDeviceId(candidate.Peer.DeviceId),
            candidate.Peer.PublicKeyFingerprint), crypto, localIdentity, localPairing);
    }

    internal async Task<CurrentPathProtocolIdentityBinding> AccountIdentityAsync(CancellationToken cancellationToken)
    {
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _identity ??= await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, cancellationToken).ConfigureAwait(false);
            var material = _identity.PublicMaterial;
            return new CurrentPathProtocolIdentityBinding(material.DeviceId,
                CurrentPathProtocolSigningAlgorithm.MLDsa65, material.ProtocolPublicKey, material.ProtocolPublicKeyFingerprint);
        }
        finally { _operations.Release(); }
    }

    public async Task<RemoteControlHostPreparation> PrepareAsync(CancellationToken cancellationToken = default)
    {
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _identity ??= await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, cancellationToken).ConfigureAwait(false);
            return await BuildPreparationAsync(_identity, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _operations.Release();
        }
    }

    public async Task<RemoteControlHostPreparation> ImportTrustedPeerAsync(RemoteControlPairingMaterial material, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(material);
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_host is not null || HasIncomingMain)
            {
                throw new InvalidOperationException("Stop incoming connections before changing the trusted peer list.");
            }

            _identity ??= await RemoteControlIdentityStore.LoadOrCreateAsync(_stateDirectory, _displayName, cancellationToken).ConfigureAwait(false);
            // Complete fallible network discovery before committing authority. A
            // later adapter failure must not report an already trusted peer as unimported.
            var preparation = await BuildPreparationAsync(_identity, cancellationToken).ConfigureAwait(false);
            await _identity.ImportTrustedPeerAsync(material, cancellationToken).ConfigureAwait(false);
            return preparation with { TrustedDeviceNames = _identity.TrustedMaterials.Select(peer => peer.DeviceName).ToArray() };
        }
        finally
        {
            _operations.Release();
        }
    }

    public async Task StartAsync(RemoteControlNetworkInterface selectedInterface, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selectedInterface);
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_host is not null)
            {
                throw new InvalidOperationException("Remote control already owns a host. Stop it before starting another.");
            }

            var identity = _identity ?? throw new InvalidOperationException("Remote-control identity has not been prepared.");
            if (identity.TrustedMaterials.Count == 0)
            {
                throw new InvalidOperationException("Import a trusted controller before enabling remote control.");
            }

            var networks = await Task.Run(ReadNetworkInterfaces, cancellationToken).ConfigureAwait(false);
            if (!networks.Contains(selectedInterface))
            {
                throw new InvalidOperationException("The selected network is no longer available. Refresh and select the connected network again.");
            }

            var host = new WindowsRemoteControlHost(identity);
            var generation = Interlocked.Increment(ref _generation);
            Action<WindowsRemoteControlHostStatus> handler = status =>
            {
                lock (_stateGate)
                {
                    if (!ReferenceEquals(_host, host)) return;
                }

                StatusChanged?.Invoke(new RemoteControlHostWorkspaceStatus(generation, status));
            };
            CancellationTokenSource hostCancellation;
            lock (_stateGate)
            {
                hostCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                _hostCancellation = hostCancellation;
                _host = host;
                _hostStatusHandler = handler;
            }

            host.StatusChanged += handler;
            try
            {
                await host.StartAsync(selectedInterface.Address, selectedInterface.InterfaceIndex, hostCancellation.Token).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                _hostObservation = ObserveHostCompletionAsync(host, generation, hostCancellation.Token);
            }
            catch (Exception startError)
            {
                try
                {
                    await ReleaseHostAsync(host).ConfigureAwait(false);
                }
                catch (Exception cleanupError)
                {
                    throw new AggregateException("Remote-control start and cleanup failed.", startError, cleanupError);
                }

                throw;
            }
        }
        finally
        {
            _operations.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        lock (_stateGate)
        {
            _hostCancellation?.Cancel();
        }

        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_host is { } host)
            {
                await host.StopAsync().ConfigureAwait(false);
                await ReleaseHostAsync(host).ConfigureAwait(false);
            }
        }
        finally
        {
            _operations.Release();
        }
    }

    public Task ApproveSessionAsync(Guid sessionId, bool allowInput, CancellationToken cancellationToken = default) =>
        RunHostOperationAsync(host => host.ApproveSessionAsync(sessionId, allowInput, cancellationToken), cancellationToken);

    public Task TransferInputAsync(Guid sessionId, CancellationToken cancellationToken = default) =>
        RunHostOperationAsync(host => host.TransferInputAsync(sessionId, cancellationToken), cancellationToken);

    public Task DisconnectSessionAsync(Guid sessionId, CancellationToken cancellationToken = default) =>
        RunHostOperationAsync(host =>
        {
            host.DisconnectSession(sessionId);
            return Task.CompletedTask;
        }, cancellationToken);

    private async Task RunHostOperationAsync(Func<WindowsRemoteControlHost, Task> operation, CancellationToken cancellationToken)
    {
        await _operations.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var host = _host ?? throw new InvalidOperationException("Remote access is not enabled.");
            await operation(host).ConfigureAwait(false);
        }
        finally { _operations.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        await StopIncomingMainAsync().ConfigureAwait(false);
        await DisconnectControlSessionsAsync().ConfigureAwait(false);
        await StopAsync().ConfigureAwait(false);
        await _operations.WaitAsync().ConfigureAwait(false);
        try
        {
            _identity?.Dispose();
            _identity = null;
        }
        finally
        {
            _operations.Release();
        }
    }

    private async Task ReleaseHostAsync(WindowsRemoteControlHost host)
    {
        await host.DisposeAsync().ConfigureAwait(false);
        await _hostObservation.ConfigureAwait(false);
        lock (_stateGate)
        {
            if (!ReferenceEquals(_host, host)) return;
            host.StatusChanged -= _hostStatusHandler;
            _hostStatusHandler = null;
            _host = null;
            Interlocked.Increment(ref _generation);
            _hostObservation = Task.CompletedTask;
            _hostCancellation?.Dispose();
            _hostCancellation = null;
        }
    }

    private async Task ObserveHostCompletionAsync(WindowsRemoteControlHost host, long generation, CancellationToken cancellationToken)
    {
        try
        {
            await host.Completion.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // An explicit stop cancels the listener and all session consumers.
        }
        catch (Exception error)
        {
            lock (_stateGate)
            {
                if (!ReferenceEquals(_host, host)) return;
            }

            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "RemoteControlHost", error.Message);
            StatusChanged?.Invoke(new RemoteControlHostWorkspaceStatus(generation,
                host.CurrentStatus with { State = WindowsRemoteControlHostState.Failed, Message = error.Message }));
        }
    }

    private static async Task<RemoteControlHostPreparation> BuildPreparationAsync(RemoteControlIdentityStore identity, CancellationToken cancellationToken)
    {
        var networks = await Task.Run(ReadNetworkInterfaces, cancellationToken).ConfigureAwait(false);
        return new RemoteControlHostPreparation(
            identity.PublicMaterial.ToJson(),
            identity.PublicMaterial.DeviceName,
            identity.PublicMaterial.ProtocolPublicKeyFingerprint,
            identity.TrustedMaterials.Select(material => material.DeviceName).ToArray(),
            networks);
    }

    private static IReadOnlyList<RemoteControlNetworkInterface> ReadNetworkInterfaces()
    {
        var choices = new List<RemoteControlNetworkInterface>();
        foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (network.OperationalStatus != OperationalStatus.Up ||
                network.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel ||
                !network.Supports(NetworkInterfaceComponent.IPv4))
            {
                continue;
            }

            var properties = network.GetIPProperties();
            var ipv4 = properties.GetIPv4Properties() ?? throw new InvalidOperationException("An active IPv4 network has no interface properties.");
            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork ||
                    IPAddress.IsLoopback(unicast.Address) || unicast.Address.Equals(IPAddress.Any))
                {
                    continue;
                }

                choices.Add(new RemoteControlNetworkInterface(network.Id, network.Name, unicast.Address, checked((uint)ipv4.Index)));
            }
        }

        return choices.OrderBy(choice => choice.Name, StringComparer.CurrentCulture).ThenBy(choice => choice.Address.ToString(), StringComparer.Ordinal).ToArray();
    }
}
