using System.Buffers.Binary;
using System.Security.Cryptography;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.FileTransfer;

internal static class AudioFilePcmPlaybackTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("file PCM submits original integer bytes and a short final frame without padding", IntegerBytes),
        ("file PCM preserves finite float negative zero and subnormal bit patterns", FloatBytes),
        ("file PCM completes empty input without starting a device timeline", Empty),
        ("file PCM production entry uses the verified private artifact and retains its owner", VerifiedArtifact),
        ("file PCM re-inspects metadata through the actual reader before native submission", MetadataBinding),
        ("file PCM rejects mismatched output unknown layout range and reused output", InvalidAdmission),
        ("file PCM rejects non-finite samples before any part of their block is submitted", NonFinite),
        ("file PCM read exceptions and short reads do not become completion receipts", ReadFailures),
        ("file PCM async disk work leaves the native owner free to pace and check authority", SlowRead),
        ("file PCM cancellation stops output and awaits a late noncooperative read", CancelPendingRead),
        ("file PCM retains a late read failure alongside cancellation", CancelAndReadFailure),
        ("file PCM preserves provider cancellation callback cleanup failure", CancellationCallbackFailure),
        ("file PCM waits for native tail and actual disposal before returning a receipt", TailAndDisposal),
        ("file PCM reports real endpoint exhaustion instead of filling a gap", Underrun),
        ("file PCM rejects exhaustion first observed inside native Submit admission", SubmitAdmissionUnderrun),
        ("file PCM rejects authorization revoked while waiting for disk", RevokedDuringRead),
        ("file PCM fails a five-second source or device progress stall", ProgressDeadline),
        ("file PCM bounds prefetch to two blocks plus the current native block", BoundedPrefetch)
    ];
    private static AudioStreamingPcmFormat IntegerFormat(ushort bits = 16) => new(48000, 2,
        bits switch { 8 => AudioStreamingEncoding.Unsigned8, 16 => AudioStreamingEncoding.Signed16,
            24 => AudioStreamingEncoding.Signed24, 32 => AudioStreamingEncoding.Signed32, 64 => AudioStreamingEncoding.Signed64,
            _ => throw new ArgumentOutOfRangeException(nameof(bits)) }, (byte)bits, 3);

    private static async Task IntegerBytes()
    {
        foreach (ushort bits in new ushort[] { 8, 16, 24, 32, 64 })
        {
            var format = IntegerFormat(bits);
            int length = checked((int)(481 * format.BytesPerFrame));
            var bytes = Enumerable.Range(0, length).Select(i => (byte)(i * 73 + 3)).ToArray();
            var rig = await Rig.Create(format, bytes);
            int started = 0;
            rig.OnStarted = () => { Equal(1, rig.Native.Starts); started++; };
            var receipt = await rig.Run();
            Bytes(bytes, rig.Native.Submissions.SelectMany(b => b).ToArray());
            Equal(481UL, receipt.SourceFrames); Require(receipt.Tail is not null, "Missing nonempty device tail.");
            Require(rig.Native.Submissions.All(b => b.Length % format.BytesPerFrame == 0), "Partial frame reached native output.");
            Equal(1, rig.Native.Starts); Equal(1, rig.Native.DisposeCalls); Equal(1, rig.Device.DisposeCalls);
            Equal(1, started);
            Require(!rig.Device.WrongThread, "Native ownership moved threads.");
        }
    }

    private static async Task FloatBytes()
    {
        foreach (var (encoding, bits, hex) in new (AudioStreamingEncoding, byte, string)[]
        {
            (AudioStreamingEncoding.Float32, 32, "000000800100000001000080FFFF7F000000803F000080BF"),
            (AudioStreamingEncoding.Float64, 64, "000000000000008001000000000000000100000000000080FFFFFFFFFFFF0F00000000000000F03F000000000000F0BF")
        })
        {
            var bytes = Convert.FromHexString(hex);
            var rig = await Rig.Create(new AudioStreamingPcmFormat(48000, 2, encoding, bits, 3), bytes);
            var receipt = await rig.Run();
            Bytes(bytes, rig.Native.Submissions.SelectMany(b => b).ToArray());
            Equal(3UL, receipt.SourceFrames);
        }
    }

    private static async Task Empty()
    {
        var rig = await Rig.Create(IntegerFormat(), []);
        rig.OnStarted = () => throw new InvalidOperationException("Empty input must not announce native Start.");
        var receipt = await rig.Run();
        Equal(0UL, receipt.SourceFrames); Require(receipt.Tail is null, "Empty input invented a tail timeline.");
        Equal(0, rig.Native.Starts); Equal(0, rig.Native.Submissions.Count);
        Equal(1, rig.Native.DisposeCalls); Equal(1, rig.Device.DisposeCalls);
    }

    private static async Task VerifiedArtifact()
    {
        var rig = await Rig.Create(IntegerFormat(24), Enumerable.Range(0, 600).Select(i => (byte)i).ToArray());
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var metadata = ClassicFileTransferWire.Authenticate(new ClassicFileMetadata(Guid.NewGuid().ToString("D"),
            "original.wav", rig.Wave.Length, Convert.ToHexStringLower(SHA256.HashData(rig.Wave)), 65536, 2), key);
        using var wire = new MemoryStream();
        await ClassicFileTransferFrames.WriteAsync(wire, ClassicFileFrameType.Chunk,
            ClassicFileTransferWire.Encode(ClassicFileTransferWire.SealChunk(0, rig.Wave, key)), default);
        await ClassicFileTransferFrames.WriteAsync(wire, ClassicFileFrameType.Complete, ReadOnlyMemory<byte>.Empty, default);
        wire.Position = 0;
        string directory = Path.Combine(AppContext.BaseDirectory, "file-pcm-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        AudioOriginalFileArtifact? artifact = null;
        try
        {
            artifact = await AudioOriginalFileArtifact.ReceiveAsync(wire, metadata, key, directory, () => { }, default);
            var inspected = await artifact.InspectWaveAsync(default);
            Equal(rig.Metadata, inspected);
            var receipt = await rig.Run(artifact: artifact);
            Equal(100UL, receipt.SourceFrames); Bytes(rig.Pcm, rig.Native.Submissions.SelectMany(b => b).ToArray());
            Require(!artifact.IsReleased, "The pump disposed the caller's artifact.");
            Bytes(rig.Pcm, await artifact.ReadAsync(inspected.PcmByteOffset, rig.Pcm.Length, default));
        }
        finally
        {
            if (artifact is not null) await artifact.DisposeAsync();
            CryptographicOperations.ZeroMemory(key);
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task MetadataBinding()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[4]);
        var altered = rig.Wave.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(altered.AsSpan(24), 44100);
        BinaryPrimitives.WriteUInt32LittleEndian(altered.AsSpan(28), 44100 * 4);
        rig.Read = (offset, count, token) => Task.FromResult(altered.AsSpan(checked((int)offset), count).ToArray());
        await Throws<InvalidDataException>(() => rig.Run());
        Equal(0, rig.Native.Submissions.Count); Equal(0, rig.Native.Starts);
    }

    private static async Task InvalidAdmission()
    {
        foreach (string mode in new[] { "format", "layout", "range", "partial", "reuse" })
        {
            var rig = await Rig.Create(IntegerFormat(), new byte[4]);
            if (mode == "format") rig.OutputFormat = new ExactPcmFormat(44100, 2, 16, 16, false, 3);
            if (mode == "layout") rig.Metadata = new(new AudioStreamingPcmFormat(48000, 2, AudioStreamingEncoding.Signed16, 16, null), 68, 4);
            if (mode == "range") rig.Metadata = new(IntegerFormat(), long.MaxValue, 4);
            if (mode == "partial") rig.Metadata = new(IntegerFormat(), 68, 3);
            if (mode == "reuse") rig.BeforePlay = output => output.Submit(new byte[4], 0, 4);
            if (mode == "reuse") await Throws<InvalidOperationException>(() => rig.Run());
            else await Throws<InvalidDataException>(() => rig.Run());
            Equal(0, rig.ReadCalls);
            Equal(mode == "reuse" ? 1 : 0, rig.Native.Submissions.Count);
        }
    }

    private static async Task NonFinite()
    {
        foreach (var (bits, patterns) in new (byte, ulong[])[]
        {
            (32, [0x7fc12345, 0x7f800000, 0xff800000]),
            (64, [0x7ff8123456789abc, 0x7ff0000000000000, 0xfff0000000000000])
        })
            foreach (ulong pattern in patterns)
            {
                var bytes = new byte[bits / 8 * 2];
                if (bits == 32) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)pattern);
                else BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(8), pattern);
                var rig = await Rig.Create(new(48000, 2, bits == 32 ? AudioStreamingEncoding.Float32 : AudioStreamingEncoding.Float64, bits, 3), bytes);
                var error = await Throws<AudioFilePcmPlaybackException>(() => rig.Run());
                Equal(AudioStreamingStopReason.UnsupportedSource, error.Reason); Equal(0, rig.Native.Submissions.Count);
            }
    }

    private static async Task ReadFailures()
    {
        foreach (bool shortRead in new[] { false, true })
        {
            var rig = await Rig.Create(IntegerFormat(), new byte[4]);
            var original = new IOException("Source read failed.");
            rig.Read = (offset, count, token) => offset < rig.Metadata.PcmByteOffset ? rig.ReadMemory(offset, count) :
                shortRead ? Task.FromResult(new byte[count - 1]) : Task.FromException<byte[]>(original);
            if (shortRead) await Throws<InvalidDataException>(() => rig.Run());
            else Require(ReferenceEquals(original, await Throws<IOException>(() => rig.Run())), "Read failure was replaced.");
            Equal(0, rig.Native.Submissions.Count); Equal(0, rig.Native.Starts);
        }
    }

    private static async Task SlowRead()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[4]);
        var entered = Signal(); using var release = new ManualResetEventSlim();
        int readThread = 0;
        rig.Read = (offset, count, token) =>
        {
            if (offset < rig.Metadata.PcmByteOffset) return rig.ReadMemory(offset, count);
            readThread = Environment.CurrentManagedThreadId; entered.TrySetResult();
            release.Wait(); // Even a synchronously blocked provider must not occupy the native worker.
            return rig.ReadMemory(offset, count);
        };
        var run = rig.Run();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            int before = Volatile.Read(ref rig.Native.Waits);
            await Until(() => Volatile.Read(ref rig.Native.Waits) > before);
            Require(!run.IsCompleted, "Pending read produced an early receipt.");
            Require(readThread != rig.Device.OwnerThread && !rig.Device.WrongThread, "Disk callback ran on the native owner.");
        }
        finally { release.Set(); }
        Equal(1UL, (await run).SourceFrames);
    }

    private static async Task CancelPendingRead()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[AudioFilePcmPlayback.MaximumBlockBytes * 2]);
        using var cancellation = new CancellationTokenSource();
        var entered = Signal(); var release = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        rig.Native.Retire = false;
        rig.Read = (offset, count, token) =>
        {
            if (offset < rig.Metadata.PcmByteOffset + AudioFilePcmPlayback.MaximumBlockBytes) return rig.ReadMemory(offset, count);
            entered.TrySetResult(); return release.Task; // Intentionally ignores cancellation.
        };
        var run = rig.Run(cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Until(() => Volatile.Read(ref rig.Native.Starts) == 1);
            cancellation.Cancel();
            await rig.Native.Stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Require(!run.IsCompleted, "Read owner was abandoned before its callback completed.");
            // Pace can itself fail and release native output on cancellation. The
            // independent disk producer must still remain owned until it returns.
            Require(!rig.Device.WrongThread, "Native cancellation cleanup changed its owner thread.");
        }
        finally { release.TrySetResult(new byte[AudioFilePcmPlayback.MaximumBlockBytes]); }
        await Throws<OperationCanceledException>(() => run);
        Equal(1, rig.Native.DisposeCalls); Require(!rig.Device.WrongThread, "Cancellation moved native cleanup threads.");
    }

    private static async Task CancelAndReadFailure()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[4]);
        using var cancellation = new CancellationTokenSource();
        var entered = Signal(); var release = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var original = new IOException("Late disk failure.");
        rig.Read = (offset, count, token) =>
        {
            if (offset < rig.Metadata.PcmByteOffset) return rig.ReadMemory(offset, count);
            entered.TrySetResult(); return release.Task;
        };
        var run = rig.Run(cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Until(() => rig.Output?.State is ExclusivePcmOutputState.Stopped or ExclusivePcmOutputState.Faulted);
        Require(!run.IsCompleted, "Canceled read was detached.");
        release.SetException(original);
        var failure = await Throws<AggregateException>(() => run);
        Require(Errors(failure).Any(e => ReferenceEquals(e, original)) && Errors(failure).Any(e => e is OperationCanceledException),
            "Cancellation or late read cause was lost.");
    }

    private static async Task CancellationCallbackFailure()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[4]);
        using var cancellation = new CancellationTokenSource();
        var entered = Signal(); var release = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var original = new IOException("Provider cancellation cleanup failed.");
        rig.Read = async (offset, count, token) =>
        {
            if (offset < rig.Metadata.PcmByteOffset) return await rig.ReadMemory(offset, count);
            using var registration = token.Register(() => throw original);
            entered.TrySetResult(); return await release.Task;
        };
        var run = rig.Run(cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            await Until(() => rig.Output?.State is ExclusivePcmOutputState.Stopped or ExclusivePcmOutputState.Faulted);
            Require(!run.IsCompleted, "Cancellation cleanup failure abandoned the pending read.");
        }
        finally { release.TrySetResult(new byte[4]); }
        var failure = await Throws<AggregateException>(() => run);
        Require(Errors(failure).Any(e => ReferenceEquals(e, original)) && Errors(failure).Any(e => e is OperationCanceledException),
            "Provider cancellation failure or caller cancellation was lost.");
    }

    private static async Task TailAndDisposal()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[4]);
        rig.Native.Latency = TimeSpan.FromMilliseconds(8);
        rig.Native.BlockDispose = true;
        var run = rig.Run();
        try
        {
            await rig.Native.DisposeEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Require(!run.IsCompleted, "Receipt preceded actual native disposal.");
            Require(rig.Clock.GetTimestamp() >= rig.Native.Latency.Ticks && rig.Native.Position > 0,
                "Native tail omitted host time or device progress.");
        }
        finally { rig.Native.DisposeRelease.Set(); }
        var receipt = await run;
        Require(receipt.Tail is { } tail && tail.HostElapsed >= rig.Native.Latency, "Tail was shortened.");
        Equal(1, rig.Device.DisposeCalls); Equal(ExclusivePcmOutputState.Completed, rig.Output!.State);
    }

    private static async Task Underrun()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[481 * 4]);
        rig.Native.DrainAll = true;
        var failure = await Throws<AudioFilePcmPlaybackException>(() => rig.Run());
        Equal(AudioStreamingStopReason.OutputLost, failure.Reason);
        Equal(480 * 4, rig.Native.Submissions.Sum(b => b.Length));
        Require(rig.Output!.State != ExclusivePcmOutputState.Completed, "Underrun was hidden by a completion receipt.");
    }

    private static async Task RevokedDuringRead()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[4]);
        var entered = Signal(); var release = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        int revoked = 0; var original = new InvalidOperationException("Permission revoked.");
        rig.Authorization = () => { if (Volatile.Read(ref revoked) != 0) throw original; };
        rig.Read = (offset, count, token) =>
        {
            if (offset < rig.Metadata.PcmByteOffset) return rig.ReadMemory(offset, count);
            entered.TrySetResult(); return release.Task;
        };
        var run = rig.Run();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Volatile.Write(ref revoked, 1);
        await Until(() => rig.Output?.State == ExclusivePcmOutputState.Stopped);
        Require(!run.IsCompleted, "Revocation detached the read owner.");
        release.SetResult(new byte[4]);
        Require(ReferenceEquals(original, await Throws<InvalidOperationException>(() => run)), "Revocation failure was replaced.");
        Equal(0, rig.Native.Submissions.Count);
    }

    private static async Task SubmitAdmissionUnderrun()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[481 * 4]);
        rig.Native.DrainDuringSubmitAdmission = true;
        await Throws<IOException>(() => rig.Run());
        Equal(480 * 4, rig.Native.Submissions.Sum(b => b.Length));
        Require(rig.Output!.State != ExclusivePcmOutputState.Completed, "Submission hid a fresh native empty-queue observation.");
    }

    private static async Task ProgressDeadline()
    {
        foreach (bool deviceStall in new[] { false, true })
        {
            var rig = await Rig.Create(IntegerFormat(), new byte[(deviceStall ? 481 : 1) * 4]);
            rig.Native.Retire = !deviceStall;
            var entered = Signal(); var release = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!deviceStall) rig.Read = (offset, count, token) =>
            {
                if (offset < rig.Metadata.PcmByteOffset) return rig.ReadMemory(offset, count);
                entered.TrySetResult(); return release.Task;
            };
            var run = rig.Run();
            if (deviceStall) await Until(() => Volatile.Read(ref rig.Native.Starts) == 1);
            else await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            rig.Clock.Advance(TimeSpan.FromSeconds(6));
            if (!deviceStall)
            {
                await Until(() => rig.Output?.State == ExclusivePcmOutputState.Stopped);
                Require(!run.IsCompleted, "Deadline abandoned the live read.");
                release.SetResult(new byte[4]);
            }
            await Throws<TimeoutException>(() => run);
        }
    }

    private static async Task BoundedPrefetch()
    {
        var rig = await Rig.Create(IntegerFormat(), new byte[AudioFilePcmPlayback.MaximumBlockBytes * 6]);
        using var cancellation = new CancellationTokenSource();
        rig.Native.Retire = false;
        int pcmReads = 0;
        rig.Read = (offset, count, token) =>
        {
            if (offset >= rig.Metadata.PcmByteOffset)
            {
                Require(count <= 65536 && count % 4 == 0, "Prefetch violated block/frame limits.");
                Interlocked.Increment(ref pcmReads);
            }
            return rig.ReadMemory(offset, count);
        };
        var run = rig.Run(cancellation.Token);
        await Until(() => Volatile.Read(ref pcmReads) == 3 && Volatile.Read(ref rig.Native.Starts) == 1);
        int before = Volatile.Read(ref rig.Native.Waits);
        await Until(() => Volatile.Read(ref rig.Native.Waits) >= before + 5);
        Equal(3, Volatile.Read(ref pcmReads));
        cancellation.Cancel(); await Throws<OperationCanceledException>(() => run);
    }

    private sealed class Rig
    {
        internal byte[] Pcm = [], Wave = [];
        internal AudioWavePcmMetadata Metadata = null!;
        internal ExactPcmFormat OutputFormat = null!;
        internal readonly Clock Clock = new();
        internal readonly Device Device;
        internal Native Native => Device.Client;
        internal ExclusivePcmOutput? Output;
        internal int ReadCalls;
        internal Func<long, int, CancellationToken, Task<byte[]>> Read = null!;
        internal Action Authorization = () => { };
        internal Action? OnStarted;
        internal Action<ExclusivePcmOutput>? BeforePlay;
        private Rig() { Device = new(Clock); }
        internal static async Task<Rig> Create(AudioStreamingPcmFormat format, byte[] pcm)
        {
            var rig = new Rig { Pcm = pcm, OutputFormat = format.RequireExactOutputFormat() };
            rig.Wave = AudioFilePcmPlaybackTests.Wave(format, pcm);
            rig.Metadata = await AudioWavePcmFile.InspectAsync(rig.Wave.Length,
                (offset, count, token) => rig.ReadMemory(offset, count), default);
            rig.Read = (offset, count, token) => rig.ReadMemory(offset, count);
            return rig;
        }
        internal Task<byte[]> ReadMemory(long offset, int count) => Task.FromResult(Wave.AsSpan(checked((int)offset), count).ToArray());
        internal Task<ExclusivePcmPlaybackReceipt> Run(CancellationToken token = default, AudioOriginalFileArtifact? artifact = null) =>
            Task.Factory.StartNew(() =>
            {
                var output = ExclusivePcmOutput.Open(Device, OutputFormat, 480, Clock); Output = output;
                Exception? primary = null;
                try
                {
                    BeforePlay?.Invoke(output);
                    return artifact is not null
                        ? AudioFilePcmPlayback.Play(artifact, Metadata, output, Authorization, token, Clock, OnStarted)
                        : AudioFilePcmPlayback.Play(Wave.Length, (offset, count, cancellation) =>
                        { Interlocked.Increment(ref ReadCalls); return Read(offset, count, cancellation); },
                            Metadata, output, Authorization, token, Clock, OnStarted);
                }
                catch (Exception error) { primary = error; throw; }
                finally
                {
                    try { output.Dispose(); }
                    catch (Exception cleanup) when (primary is not null) { throw new AggregateException(primary, cleanup); }
                }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    private sealed class Clock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref _ticks);
        internal void Advance(TimeSpan duration) => Interlocked.Add(ref _ticks, duration.Ticks);
    }
    private sealed class Device : IExclusivePcmDevice
    {
        internal readonly Native Client;
        internal int OwnerThread, DisposeCalls;
        internal bool WrongThread;
        internal Device(Clock clock) { Client = new(this, clock); }
        internal void Touch()
        {
            int thread = Environment.CurrentManagedThreadId, original = Interlocked.CompareExchange(ref OwnerThread, thread, 0);
            if (original != 0 && original != thread) { WrongThread = true; throw new InvalidOperationException("Native owner changed thread."); }
        }
        public IExclusivePcmClient Activate() { Touch(); return Client; }
        public void Dispose() { Touch(); DisposeCalls++; }
    }
    private sealed class Native(Device owner, Clock clock) : IExclusivePcmClient
    {
        private ExactPcmFormat _format = null!;
        private uint _queued;
        private bool _running;
        internal ulong Position;
        internal readonly List<byte[]> Submissions = [];
        internal int Starts, Waits, DisposeCalls;
        internal volatile bool Retire = true, DrainAll, DrainDuringSubmitAdmission, BlockDispose;
        private int _queueReadsSinceStart;
        internal TimeSpan Latency = TimeSpan.FromMilliseconds(1);
        internal readonly TaskCompletionSource Stopped = Signal(), DisposeEntered = Signal();
        internal readonly ManualResetEventSlim DisposeRelease = new();
        public int IsExactFormatSupported(ExactPcmFormat format) { owner.Touch(); return 0; }
        public int Initialize(ExactPcmFormat format, long duration) { owner.Touch(); _format = format; return 0; }
        public uint GetBufferFrames() { owner.Touch(); return 480; }
        public int GetStreamLatency(out long latency) { owner.Touch(); latency = Latency.Ticks; return 0; }
        public void Prepare() { owner.Touch(); }
        public uint GetQueuedFrames()
        {
            owner.Touch();
            // First read: pump ObserveProgress sees queued samples. Second read:
            // Submit's own admission sees that the device exhausted meanwhile.
            if (_running && ++_queueReadsSinceStart == 2 && DrainDuringSubmitAdmission) _queued = 0;
            return _queued;
        }
        public int GetClockPosition(out ulong position, out ulong frequency)
        { owner.Touch(); position = Position; frequency = _format.SampleRate; return 0; }
        public void Submit(byte[] bytes, int offset, int count, uint frames)
        {
            owner.Touch(); Require(frames <= 480 - _queued && count == (long)frames * _format.BytesPerFrame, "Invalid native packet.");
            Submissions.Add(bytes.AsSpan(offset, count).ToArray()); _queued += frames;
        }
        public void Start() { owner.Touch(); _running = true; _queueReadsSinceStart = 0; Interlocked.Increment(ref Starts); }
        public void WaitForProgress(TimeSpan delay, CancellationToken token)
        {
            owner.Touch(); token.ThrowIfCancellationRequested(); Interlocked.Increment(ref Waits);
            clock.Advance(delay);
            if (_running && Retire)
            {
                _queued -= DrainAll ? _queued : Math.Min(_queued, 120U);
                Position += Math.Max(1UL, (ulong)delay.Ticks * _format.SampleRate / TimeSpan.TicksPerSecond);
            }
            Thread.Sleep(1); token.ThrowIfCancellationRequested();
        }
        public void Stop() { owner.Touch(); _running = false; Stopped.TrySetResult(); }
        public void Dispose()
        {
            owner.Touch(); DisposeCalls++; DisposeEntered.TrySetResult(); if (BlockDispose) DisposeRelease.Wait();
        }
    }

    private static byte[] Wave(AudioStreamingPcmFormat format, byte[] pcm)
    {
        byte[] result = new byte[68 + pcm.Length + (pcm.Length & 1)];
        "RIFF"u8.CopyTo(result); BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), (uint)result.Length - 8);
        "WAVEfmt "u8.CopyTo(result.AsSpan(8)); BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(16), 40);
        format.RequireExactOutputFormat().ToWaveFormatExtensible().CopyTo(result, 20);
        "data"u8.CopyTo(result.AsSpan(60)); BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(64), (uint)pcm.Length);
        pcm.CopyTo(result, 68); return result;
    }
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task Until(Func<bool> predicate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!predicate()) await Task.Delay(1, timeout.Token);
    }
    private static IEnumerable<Exception> Errors(Exception error) => error is AggregateException aggregate
        ? new[] { error }.Concat(aggregate.InnerExceptions.SelectMany(Errors))
        : error.InnerException is { } inner ? new[] { error }.Concat(Errors(inner)) : [error];
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static void Bytes(byte[] expected, byte[] actual) => Require(expected.SequenceEqual(actual), "PCM bytes changed.");
    private static void Equal<T>(T expected, T actual) => Require(EqualityComparer<T>.Default.Equals(expected, actual), $"Expected {expected}; got {actual}.");
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
}
