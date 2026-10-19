using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using static Skybridge.WinClient.Services.Audio.AudioOutputNativeMetadata;

namespace Skybridge.WinClient.Services.Audio;

// Every call, including Dispose, belongs on the same dedicated worker thread.
// This class never changes the endpoint's shared mix format or system volume.
[SupportedOSPlatform("windows")]
internal sealed class WindowsExclusivePcmDevice : IExclusivePcmDevice
{
    private static readonly Guid EnumeratorClass = new("BCDE0395-E52F-467C-8E3D-C4579291692E");
    private static readonly Guid EnumeratorInterface = new("A95664D2-9614-4F35-A746-DE8DB63617E6");
    private static readonly Guid AudioClientInterface = new("1CB9AD4C-DBFA-4C32-B178-C2F568A703B2");
    private static readonly Guid RenderClientInterface = new("F294ACFC-3146-4483-A7BF-ADDCA7C260E2");
    private static readonly Guid AudioClockInterface = new("CD63314F-3FBA-4A1B-812C-EF96358728E7");
    private readonly int _threadId = Environment.CurrentManagedThreadId;
    private IMMDeviceEnumerator? _enumerator;
    private IMMDevice? _device;
    private bool _comInitialized;
    private bool _disposed;
    private AggregateException? _cleanupFailure;

    private WindowsExclusivePcmDevice() { }

    // Read-only active render endpoints. Run the whole synchronous call on one worker;
    // it neither reads a default endpoint nor activates an audio client or probes formats.
    internal static IReadOnlyList<AudioOutputEndpoint> ReadOutputs(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Audio endpoint enumeration requires Windows.");
        return AudioOutputCatalog.Read(() => OutputEnumeration.Open(cancellationToken), cancellationToken);
    }

    public static WindowsExclusivePcmDevice Open(string endpointId)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("WASAPI requires Windows.");
        if (string.IsNullOrWhiteSpace(endpointId) || endpointId.Length > 32768)
            throw new ArgumentException("An explicit output endpoint ID is required.", nameof(endpointId));
        var owner = new WindowsExclusivePcmDevice();
        try
        {
            ExclusivePcmOutput.RequireSuccess(CoInitializeEx(IntPtr.Zero, 0), "initialize output COM apartment");
            owner._comInitialized = true; // S_FALSE still requires CoUninitialize.
            var classId = EnumeratorClass;
            var interfaceId = EnumeratorInterface;
            ExclusivePcmOutput.RequireSuccess(CoCreateInstance(ref classId, IntPtr.Zero, 23,
                ref interfaceId, out var enumerator), "create output endpoint enumerator");
            owner._enumerator = enumerator;
            ExclusivePcmOutput.RequireSuccess(enumerator.GetDevice(endpointId, out var device), "resolve selected output endpoint");
            owner._device = device;
            return owner;
        }
        catch (Exception failure)
        {
            try { owner.Dispose(); }
            catch (Exception cleanup) { throw new ExclusivePcmOpenCleanupException([failure, cleanup], owner, null); }
            throw;
        }
    }

    public IExclusivePcmClient Activate()
    {
        RequireThread(_threadId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        var device = _device ?? throw new InvalidOperationException("Output device is not open.");
        var interfaceId = AudioClientInterface;
        ExclusivePcmOutput.RequireSuccess(device.Activate(ref interfaceId, 23, IntPtr.Zero,
            out var instance), "activate exclusive output client");
        try { return new Client((IAudioClient)instance); }
        catch (Exception failure)
        {
            try { Marshal.ReleaseComObject(instance); }
            catch (Exception cleanup) { throw new AggregateException("Client activation and release failed.", failure, cleanup); }
            throw;
        }
    }

    public void Dispose()
    {
        RequireThread(_threadId);
        if (_disposed)
        {
            if (_cleanupFailure is not null) throw _cleanupFailure;
            return;
        }
        _disposed = true;
        var errors = new List<Exception>();
        if (_device is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_device); _device = null; }, errors);
        if (_enumerator is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_enumerator); _enumerator = null; }, errors);
        if (_comInitialized) CoUninitialize();
        _comInitialized = false;
        if (errors.Count > 0)
        {
            _cleanupFailure = new AggregateException("Output device release is unconfirmed.", errors);
            throw _cleanupFailure;
        }
    }

    private sealed class Client(IAudioClient audio) : IExclusivePcmClient
    {
        private readonly int _threadId = Environment.CurrentManagedThreadId;
        private WindowsAudioRenderPacing? _pacing;
        private object? _renderObject;
        private IExclusivePcmPacketPort? _packetPort;
        private object? _clockObject;
        private ulong _clockFrequency;
        private bool _startAttempted;
        private bool _disposed;
        private AggregateException? _cleanupFailure;
        private ExactPcmFormat? _format;
        private uint _bufferFrames;

        public int IsExactFormatSupported(ExactPcmFormat format)
        {
            Check();
            // EXCLUSIVE and a null closest-format pointer: no approximate/shared alternative.
            return WithFormat(format, pointer => audio.IsFormatSupported(1, pointer, IntPtr.Zero));
        }

        public int Initialize(ExactPcmFormat format, long bufferDuration100Nanoseconds)
        {
            Check();
            // Non-event EXCLUSIVE permits exact finite tails. Use the endpoint's default period;
            // never enable AUTOCONVERTPCM, SRC_DEFAULT_QUALITY, LOOPBACK or offload.
            var result = WithFormat(format, pointer => audio.Initialize(1, 0,
                bufferDuration100Nanoseconds, 0, pointer, IntPtr.Zero));
            if (result == 0) _format = format;
            return result;
        }

        public uint GetBufferFrames()
        {
            Check();
            ExclusivePcmOutput.RequireSOk(audio.GetBufferSize(out var frames), "query exclusive buffer size");
            _bufferFrames = frames;
            return frames;
        }

        public int GetStreamLatency(out long latency100Nanoseconds)
        {
            Check();
            return audio.GetStreamLatency(out latency100Nanoseconds);
        }

        public void Prepare()
        {
            Check();
            if (_renderObject is not null) throw new InvalidOperationException("Render client is already prepared.");
            if (_format is null || _bufferFrames == 0) throw new InvalidOperationException("Output format and buffer are not initialized.");
            var interfaceId = RenderClientInterface;
            ExclusivePcmOutput.RequireSOk(audio.GetService(ref interfaceId, out var render), "obtain render client");
            _renderObject = render;
            if (render is not IAudioRenderClient renderer) throw new InvalidCastException("Endpoint did not return an audio render client.");
            _packetPort = new PacketPort(renderer);
            interfaceId = AudioClockInterface;
            ExclusivePcmOutput.RequireSOk(audio.GetService(ref interfaceId, out var clock), "obtain output clock");
            _clockObject = clock;
            if (clock is not IAudioClock clockClient) throw new InvalidCastException("Endpoint did not return an audio clock.");
            ExclusivePcmOutput.RequireSOk(clockClient.GetFrequency(out _clockFrequency), "query output device clock frequency");
            if (_clockFrequency == 0) throw new InvalidDataException("Output device clock frequency is zero.");
            _pacing = new WindowsAudioRenderPacing();
        }

        public uint GetQueuedFrames()
        {
            Check();
            ExclusivePcmOutput.RequireSOk(audio.GetCurrentPadding(out var queued), "read queued output frames");
            return queued;
        }
        public int GetClockPosition(out ulong position, out ulong frequency)
        {
            Check();
            var clock = _clockObject as IAudioClock ?? throw new InvalidOperationException("Output clock is not prepared.");
            frequency = _clockFrequency;
            return clock.GetPosition(out position, IntPtr.Zero);
        }

        public void Submit(byte[] bytes, int offset, int count, uint frames)
        {
            Check();
            var packet = _packetPort ?? throw new InvalidOperationException("Render client is not prepared.");
            // Validate before acquiring a native packet. No allocation, cancellation or await while held.
            ArgumentNullException.ThrowIfNull(bytes);
            var format = _format ?? throw new InvalidOperationException("Output format is not initialized.");
            ExclusivePcmPacketBounds.Validate(bytes.Length, offset, count, frames, _bufferFrames, format.BytesPerFrame);
            var queued = GetQueuedFrames();
            if (queued > _bufferFrames || frames > _bufferFrames - queued)
                throw new InvalidOperationException("The selected output endpoint has insufficient writable space.");
            ExclusivePcmPacketWriter.Write(packet, bytes, offset, count, frames);
            // Any failure stops this owner. Discarding an unsubmitted packet never counts as PCM.
        }

        public void Start()
        {
            Check();
            var pacing = _pacing ?? throw new InvalidOperationException("Output pacing is not prepared.");
            if (_startAttempted) throw new InvalidOperationException("Output client cannot be started twice.");
            pacing.Start();
            _startAttempted = true;
            ExclusivePcmOutput.RequireSOk(audio.Start(), "start exclusive output");
        }

        public void WaitForProgress(TimeSpan delay, CancellationToken cancellationToken)
        {
            Check();
            var pacing = _pacing ?? throw new InvalidOperationException("Output pacing is not prepared.");
            pacing.Wait(delay, cancellationToken);
        }

        public void Stop()
        {
            Check();
            if (!_startAttempted) return;
            ExclusivePcmOutput.RequireStopped(audio.Stop());
            _startAttempted = false;
        }

        public void Dispose()
        {
            RequireThread(_threadId);
            if (_disposed)
            {
                if (_cleanupFailure is not null) throw _cleanupFailure;
                return;
            }
            var errors = new List<Exception>();
            ExclusivePcmOutput.Attempt(Stop, errors);
            _disposed = true;
            if (_pacing is not null) ExclusivePcmOutput.Attempt(() => { _pacing.Dispose(); _pacing = null; }, errors);
            if (_renderObject is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_renderObject); _renderObject = null; _packetPort = null; }, errors);
            if (_clockObject is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_clockObject); _clockObject = null; }, errors);
            ExclusivePcmOutput.Attempt(() => Marshal.ReleaseComObject(audio), errors);
            if (errors.Count > 0)
            {
                _cleanupFailure = new AggregateException("Exclusive output client release is unconfirmed.", errors);
                throw _cleanupFailure;
            }
        }

        private void Check()
        {
            RequireThread(_threadId);
            ObjectDisposedException.ThrowIf(_disposed, this);
        }
    }

    private sealed class PacketPort(IAudioRenderClient render) : IExclusivePcmPacketPort
    {
        public IntPtr Acquire(uint frames)
        {
            ExclusivePcmOutput.RequireSOk(render.GetBuffer(frames, out var buffer), "obtain exclusive render buffer");
            return buffer;
        }
        public void Copy(byte[] bytes, int offset, IntPtr destination, int count) => Marshal.Copy(bytes, offset, destination, count);
        public void Release(uint frames) => ExclusivePcmOutput.RequireSOk(render.ReleaseBuffer(frames, 0),
            frames == 0 ? "discard an unsubmitted render packet" : "submit exact source frame packet");
    }

    private static int WithFormat(ExactPcmFormat format, Func<IntPtr, int> call)
    {
        var bytes = format.ToWaveFormatExtensible();
        var memory = Marshal.AllocCoTaskMem(bytes.Length);
        try { Marshal.Copy(bytes, 0, memory, bytes.Length); return call(memory); }
        finally { Marshal.FreeCoTaskMem(memory); }
    }

    private static void RequireThread(int threadId)
    {
        if (Environment.CurrentManagedThreadId != threadId)
            throw new InvalidOperationException("Native audio resources must remain on their owning thread.");
    }

    private sealed class OutputEnumeration : IAudioOutputCatalogEnumeration
    {
        private readonly int _threadId = Environment.CurrentManagedThreadId;
        private IMMDeviceEnumerator? _enumerator;
        private IMMDeviceCollection? _collection;
        private bool _initialized, _disposed;
        private Exception? _cleanupFailure;
        internal static IAudioOutputCatalogEnumeration Open(CancellationToken cancellationToken)
        {
            var owner = new OutputEnumeration();
            try
            {
                ExclusivePcmOutput.RequireSuccess(CoInitializeEx(IntPtr.Zero, 0), "initialize output catalog COM apartment");
                owner._initialized = true;
                cancellationToken.ThrowIfCancellationRequested();
                var classId = EnumeratorClass; var interfaceId = EnumeratorInterface;
                ExclusivePcmOutput.RequireSOk(CoCreateInstance(ref classId, IntPtr.Zero, 23, ref interfaceId, out owner._enumerator), "create output catalog enumerator");
                cancellationToken.ThrowIfCancellationRequested();
                ExclusivePcmOutput.RequireSOk((owner._enumerator ?? throw new InvalidDataException("Native output enumerator is null.")).EnumAudioEndpoints(0, 1, out owner._collection), "enumerate active render endpoints");
                cancellationToken.ThrowIfCancellationRequested();
                return owner;
            }
            catch (Exception failure)
            {
                try { owner.Dispose(); }
                catch (Exception cleanup) { throw new AudioOutputCatalogCleanupException([failure, cleanup], [owner]); }
                throw;
            }
        }
        public uint GetCount()
        {
            RequireThread(_threadId); ObjectDisposedException.ThrowIf(_disposed, this);
            ExclusivePcmOutput.RequireSOk((_collection ?? throw new InvalidOperationException("No output collection.")).GetCount(out uint count), "count active render endpoints");
            return count;
        }
        public IAudioOutputCatalogEndpoint GetEndpoint(uint index)
        {
            RequireThread(_threadId); ObjectDisposedException.ThrowIf(_disposed, this);
            return OutputEndpoint.Open(_collection ?? throw new InvalidOperationException("No output collection."), index);
        }
        public void Dispose()
        {
            RequireThread(_threadId);
            if (_disposed) { if (_cleanupFailure is not null) throw _cleanupFailure; return; }
            _disposed = true; var errors = new List<Exception>();
            if (_collection is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_collection); _collection = null; }, errors);
            if (_enumerator is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_enumerator); _enumerator = null; }, errors);
            if (_initialized) ExclusivePcmOutput.Attempt(() => { CoUninitialize(); _initialized = false; }, errors);
            if (errors.Count != 0) { _cleanupFailure = new AggregateException("Output catalog COM release is unconfirmed.", errors); throw _cleanupFailure; }
        }
    }

    private sealed class OutputEndpoint : IAudioOutputCatalogEndpoint
    {
        private readonly int _threadId = Environment.CurrentManagedThreadId;
        private IMMDevice? _device;
        private IPropertyStore? _properties;
        private IntPtr _id;
        private OutputPropertyVariant _name;
        private bool _idRead, _nameRead, _clearName, _disposed;
        private Exception? _cleanupFailure;
        internal static OutputEndpoint Open(IMMDeviceCollection collection, uint index)
        {
            var owner = new OutputEndpoint();
            try { ExclusivePcmOutput.RequireSOk(collection.Item(index, out owner._device), "read active output endpoint"); return owner; }
            catch (Exception failure)
            {
                try { owner.Dispose(); }
                catch (Exception cleanup) { throw new AudioOutputCatalogCleanupException([failure, cleanup], [owner]); }
                throw;
            }
        }
        public string ReadId()
        {
            RequireThread(_threadId); ObjectDisposedException.ThrowIf(_disposed, this);
            if (_idRead) throw new InvalidOperationException("Endpoint ID is read once per enumeration owner.");
            _idRead = true;
            ExclusivePcmOutput.RequireSOk((_device ?? throw new InvalidOperationException("No output endpoint.")).GetId(out _id), "read selected output endpoint ID");
            return ReadBoundedOutputString(_id, AudioOutputEndpoint.MaximumEndpointIdCharacters);
        }
        public AudioOutputName ReadName()
        {
            RequireThread(_threadId); ObjectDisposedException.ThrowIf(_disposed, this);
            if (_nameRead) throw new InvalidOperationException("Endpoint name is read once per enumeration owner.");
            _nameRead = true;
            ExclusivePcmOutput.RequireSOk((_device ?? throw new InvalidOperationException("No output endpoint.")).OpenPropertyStore(0, out _properties), "open read-only output properties");
            var key = new OutputPropertyKey { FormatId = new("A45C254E-DF1C-4EFD-8020-67D146A850E0"), PropertyId = 14 };
            _name = default; _clearName = true;
            ExclusivePcmOutput.RequireSOk((_properties ?? throw new InvalidOperationException("No output property store.")).GetValue(ref key, out _name), "read output friendly name");
            string? value = _name.Type == 31 ? ReadBoundedOutputString(_name.Value.Pointer, AudioOutputEndpoint.MaximumNameCharacters) : null;
            return AudioOutputName.FromVariant(_name.Type, value);
        }
        public void Dispose()
        {
            RequireThread(_threadId);
            if (_disposed) { if (_cleanupFailure is not null) throw _cleanupFailure; return; }
            _disposed = true; var errors = new List<Exception>();
            if (_clearName) ExclusivePcmOutput.Attempt(() => {
                ExclusivePcmOutput.RequireSOk(PropVariantClear(ref _name), "clear output friendly-name value"); _clearName = false;
            }, errors);
            if (_id != IntPtr.Zero) ExclusivePcmOutput.Attempt(() => { Marshal.FreeCoTaskMem(_id); _id = IntPtr.Zero; }, errors);
            if (_properties is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_properties); _properties = null; }, errors);
            if (_device is not null) ExclusivePcmOutput.Attempt(() => { Marshal.ReleaseComObject(_device); _device = null; }, errors);
            if (errors.Count != 0) { _cleanupFailure = new AggregateException("Output endpoint metadata release is unconfirmed.", errors); throw _cleanupFailure; }
        }
    }

    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        [PreserveSig] int EnumAudioEndpoints(int flow, uint stateMask, out IMMDeviceCollection devices);
        [PreserveSig] int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice device);
        [PreserveSig] int GetDevice([MarshalAs(UnmanagedType.LPWStr)] string id, out IMMDevice device);
        [PreserveSig] int RegisterEndpointNotificationCallback(IntPtr callback);
        [PreserveSig] int UnregisterEndpointNotificationCallback(IntPtr callback);
    }

    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        [PreserveSig] int Activate(ref Guid iid, uint context, IntPtr parameters, [MarshalAs(UnmanagedType.IUnknown)] out object instance);
        [PreserveSig] int OpenPropertyStore(uint access, out IPropertyStore properties);
        [PreserveSig] int GetId(out IntPtr id);
        [PreserveSig] int GetState(out uint state);
    }

    [ComImport, Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceCollection
    {
        [PreserveSig] int GetCount(out uint count);
        [PreserveSig] int Item(uint index, out IMMDevice device);
    }
    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPropertyStore
    {
        [PreserveSig] int GetCount(out uint count);
        [PreserveSig] int GetAt(uint index, out OutputPropertyKey key);
        [PreserveSig] int GetValue(ref OutputPropertyKey key, out OutputPropertyVariant value);
        [PreserveSig] int SetValue(ref OutputPropertyKey key, ref OutputPropertyVariant value);
        [PreserveSig] int Commit();
    }

    [ComImport, Guid("1CB9AD4C-DBFA-4C32-B178-C2F568A703B2"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioClient
    {
        [PreserveSig] int Initialize(int shareMode, uint flags, long duration, long periodicity, IntPtr format, IntPtr sessionId);
        [PreserveSig] int GetBufferSize(out uint frames);
        [PreserveSig] int GetStreamLatency(out long latency);
        [PreserveSig] int GetCurrentPadding(out uint frames);
        [PreserveSig] int IsFormatSupported(int shareMode, IntPtr format, IntPtr closestFormat);
        [PreserveSig] int GetMixFormat(out IntPtr format);
        [PreserveSig] int GetDevicePeriod(out long defaultPeriod, out long minimumPeriod);
        [PreserveSig] int Start();
        [PreserveSig] int Stop();
        [PreserveSig] int Reset();
        [PreserveSig] int SetEventHandle(IntPtr handle);
        [PreserveSig] int GetService(ref Guid iid, [MarshalAs(UnmanagedType.IUnknown)] out object service);
    }

    [ComImport, Guid("F294ACFC-3146-4483-A7BF-ADDCA7C260E2"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioRenderClient
    {
        [PreserveSig] int GetBuffer(uint frames, out IntPtr data);
        [PreserveSig] int ReleaseBuffer(uint frames, uint flags);
    }

    [ComImport, Guid("CD63314F-3FBA-4A1B-812C-EF96358728E7"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioClock
    {
        [PreserveSig] int GetFrequency(out ulong frequency);
        [PreserveSig] int GetPosition(out ulong position, IntPtr qpcPosition);
        [PreserveSig] int GetCharacteristics(out uint characteristics);
    }

    [DllImport("ole32.dll", ExactSpelling = true)] private static extern int CoInitializeEx(IntPtr reserved, uint concurrencyModel);
    [DllImport("ole32.dll", ExactSpelling = true)] private static extern void CoUninitialize();
    [DllImport("ole32.dll", ExactSpelling = true)] private static extern int PropVariantClear(ref OutputPropertyVariant value);
    [DllImport("ole32.dll", ExactSpelling = true)] private static extern int CoCreateInstance(ref Guid classId, IntPtr outer, uint context, ref Guid iid, out IMMDeviceEnumerator enumerator);
}
