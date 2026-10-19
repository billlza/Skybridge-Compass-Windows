using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Skybridge.WinClient.Services.Audio;

// Opt-in qualification of the actual file pump against WASAPI. The only input is
// a newly synthesized, one-second quiet WAVE; no account/session is created here.
internal static class NativeQuietFilePlaybackValidation
{
    // Interactive qualification only. Reuses the exact native file pump below;
    // it never registers an account, installs a service, or changes audio settings.
    [SupportedOSPlatform("windows")]
    internal static int RunLocal(string resultDirectory)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        string runId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N");
        string folder = Path.Combine(Path.GetFullPath(resultDirectory), runId);
        Directory.CreateDirectory(folder);
        string reportPath = Path.Combine(folder, "audio-report.json");
        string qualifierAssemblySha256 = Convert.ToHexStringLower(SHA256.HashData(
            File.ReadAllBytes(typeof(NativeQuietFilePlaybackValidation).Assembly.Location)));
        string[] formats = ["48000-s24-in-s32", "44100-s16", "48000-s24"];
        var results = new List<JsonElement>();
        var catalog = new List<object>();
        string status = "running";
        string? selectedEndpoint = null;
        object? failure = null;
        int exitCode = 1;
        void Save()
        {
            string pending = reportPath + ".pending";
            using (var file = new StreamWriter(new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None), new UTF8Encoding(false)))
                Write(new { schemaVersion = 1, runId, status, qualifierAssemblySha256, selectedEndpoint, catalog, results, failure,
                    notRunFormats = formats.Skip(results.Count).ToArray(),
                    os = RuntimeInformation.OSDescription, processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
                    runtime = RuntimeInformation.FrameworkDescription,
                    scope = "native-wave-file-pump", accountAndTransport = "not-tested",
                    verifiedPrivateArtifact = "not-tested", hardwareSampleIntegrity = "not-measured" }, file);
            File.Move(pending, reportPath, true);
        }
        Save(); // An interrupted run must never leave a completed-looking report.
        try
        {
            using var enumerationDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var outputs = WindowsExclusivePcmDevice.ReadOutputs(enumerationDeadline.Token);
            Console.WriteLine("SkyBridge local audio qualification / Windows audio test");
            Console.WriteLine("Select an output. Tests use one-second signals at -72 dBFS, without changing volume or sample format.");
            for (int i = 0; i < outputs.Count; i++)
            {
                var output = outputs[i];
                catalog.Add(new { number = i + 1, output.EndpointId, output.DisplayName });
                Console.WriteLine($"{i + 1}. {output.DisplayName}");
            }
            if (outputs.Count == 0) throw new InvalidOperationException("No active output endpoint was found.");
            Console.Write("Output number (0 cancels): ");
            string? choice = Console.ReadLine();
            if (choice is null || choice.Trim() == "0") { status = "cancelled"; exitCode = 2; }
            else
            {
                if (!int.TryParse(choice, out int index) || index < 1 || index > outputs.Count)
                    throw new ArgumentException("The selected output number is outside the displayed catalog.");
                selectedEndpoint = outputs[index - 1].EndpointId;
                Save();
                foreach (string format in formats)
                {
                    Console.WriteLine($"Checking {format}...");
                    using var text = new StringWriter();
                    int result = Run(selectedEndpoint, format, text);
                    string json = text.ToString();
                    File.WriteAllText(Path.Combine(folder, format + ".json"), json, new UTF8Encoding(false));
                    using var document = JsonDocument.Parse(json);
                    results.Add(document.RootElement.Clone());
                    Console.WriteLine(result == 0 ? "Completed." : "Failed or unsupported. Remaining tests will not run.");
                    if (result != 0)
                    {
                        // A failure may include uncertain native cleanup. Do not start another
                        // output owner in this process and accidentally hide that obligation.
                        status = "failed"; exitCode = result; break;
                    }
                    Save();
                }
                if (results.Count == formats.Length && status != "failed") { status = "completed"; exitCode = 0; }
            }
        }
        catch (Exception error) { status = "failed"; failure = Describe(error); }
        Save();
        Console.WriteLine($"Result: {status}");
        Console.WriteLine($"Report: {reportPath}");
        Console.WriteLine("This checks native playback only; phone connection and physical sound fidelity are not verified.");
        return exitCode;
    }

    [SupportedOSPlatform("windows")]
    internal static int Run(string endpointId, string formatName, TextWriter? report = null)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        var observation = new Observation();
        string phase = "arguments";
        try
        {
            var format = formatName switch
            {
                "44100-s16" => new AudioStreamingPcmFormat(44100, 2, AudioStreamingEncoding.Signed16, 16, 3),
                "48000-s24-in-s32" => new AudioStreamingPcmFormat(48000, 2, AudioStreamingEncoding.Signed32, 24, 3),
                "48000-s24" => new AudioStreamingPcmFormat(48000, 2, AudioStreamingEncoding.Signed24, 24, 3),
                _ => throw new ArgumentException("Use 44100-s16, 48000-s24-in-s32 or 48000-s24.")
            };
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var token = deadline.Token;
            phase = "enumerate";
            if (!WindowsExclusivePcmDevice.ReadOutputs(token).Any(endpoint => endpoint.EndpointId == endpointId))
                throw new ArgumentException("The explicit endpoint is not in the active render catalog.");
            byte[] wave = QuietWave(format);
            Task<byte[]> Read(long offset, int count, CancellationToken cancellation)
            {
                cancellation.ThrowIfCancellationRequested();
                if (offset < 0 || count <= 0 || offset > wave.Length - count)
                    throw new InvalidDataException("The requested read exceeds the immutable diagnostic source.");
                Interlocked.Increment(ref observation.SourceReads);
                return Task.FromResult(wave.AsSpan(checked((int)offset), count).ToArray());
            }
            phase = "inspect-wave";
            var metadata = AudioWavePcmFile.InspectAsync(wave.Length, Read, token).GetAwaiter().GetResult();
            if (metadata.Format != format || metadata.FrameCount != format.SampleRate)
                throw new InvalidDataException("Synthesized WAVE declarations do not match the requested one-second source.");
            byte[] pcm = wave.AsSpan(checked((int)metadata.PcmByteOffset), checked((int)metadata.PcmByteCount)).ToArray();
            phase = "open-exact-output";
            var device = new ObservedDevice(WindowsExclusivePcmDevice.Open(endpointId), pcm, observation);
            var output = ExclusivePcmOutput.Open(device, format.RequireExactOutputFormat(), format.SampleRate / 5);
            var elapsed = Stopwatch.StartNew();
            ExclusivePcmPlaybackReceipt receipt;
            Exception? primary = null;
            try
            {
                if (output.BufferFrames >= metadata.FrameCount)
                    throw new InvalidDataException("This endpoint cannot exercise refill with the one-second fixture.");
                phase = "product-file-pump";
                receipt = AudioFilePcmPlayback.Play(wave.Length, Read, metadata, output,
                    token.ThrowIfCancellationRequested, token, onStarted: () => observation.StartNotifications++);
                phase = "verify-native-result";
                if (receipt.SourceFrames != (ulong)metadata.FrameCount || receipt.Tail is null ||
                    output.State != ExclusivePcmOutputState.Completed || observation.SubmittedBytes != pcm.Length ||
                    observation.Submissions < 2 || observation.RefillSubmissions == 0 ||
                    observation.Starts != 1 || observation.StartNotifications != 1 || observation.Stops != 1 ||
                    observation.ClientReleases != 1 || observation.DeviceReleases != 1)
                    throw new InvalidDataException("The native file pump did not complete the exact source, refill and cleanup contract.");
            }
            catch (Exception error) { primary = error; throw; }
            finally
            {
                try { output.Dispose(); }
                catch (Exception cleanup)
                {
                    if (primary is not null) throw new AggregateException("File-pump qualification and cleanup failed.", primary, cleanup);
                    throw;
                }
            }
            Write(new { schemaVersion = 1, status = "completed", phase, endpointId, formatName, format,
                sourceFrames = metadata.FrameCount, sourceBytes = pcm.Length, requestedPeakDbfs = -72,
                waveSha256 = Convert.ToHexStringLower(SHA256.HashData(wave)),
                pcmSha256 = Convert.ToHexStringLower(SHA256.HashData(pcm)),
                requestedBufferFrames = format.SampleRate / 5, nativeBufferFrames = output.BufferFrames,
                nativeSubmittedBytesMatchSource = true, elapsedMilliseconds = elapsed.Elapsed.TotalMilliseconds,
                receipt, observation, os = RuntimeInformation.OSDescription,
                processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
                scope = "native-wave-file-pump", accountAndTransport = "not-tested",
                verifiedPrivateArtifact = "not-tested", hardwareSampleIntegrity = "not-measured" }, report);
            return 0;
        }
        catch (Exception error)
        {
            Write(new { schemaVersion = 1, status = "failed", phase, endpointId, formatName,
                error = Describe(error), observation, scope = "native-wave-file-pump",
                accountAndTransport = "not-tested", verifiedPrivateArtifact = "not-tested",
                hardwareSampleIntegrity = "not-measured" }, report);
            return 1;
        }
    }

    private static byte[] QuietWave(AudioStreamingPcmFormat format)
    {
        int frames = checked((int)format.SampleRate), frameBytes = checked((int)format.BytesPerFrame);
        int dataBytes = checked(frames * frameBytes), sampleBytes = format.ContainerBits / 8;
        var wave = new byte[checked(68 + dataBytes)];
        "RIFF"u8.CopyTo(wave); BinaryPrimitives.WriteUInt32LittleEndian(wave.AsSpan(4), checked((uint)wave.Length - 8));
        "WAVEfmt "u8.CopyTo(wave.AsSpan(8)); BinaryPrimitives.WriteUInt32LittleEndian(wave.AsSpan(16), 40);
        BinaryPrimitives.WriteUInt16LittleEndian(wave.AsSpan(20), 0xfffe);
        BinaryPrimitives.WriteUInt16LittleEndian(wave.AsSpan(22), format.Channels);
        BinaryPrimitives.WriteUInt32LittleEndian(wave.AsSpan(24), format.SampleRate);
        BinaryPrimitives.WriteUInt32LittleEndian(wave.AsSpan(28), checked(format.SampleRate * format.BytesPerFrame));
        BinaryPrimitives.WriteUInt16LittleEndian(wave.AsSpan(32), checked((ushort)frameBytes));
        BinaryPrimitives.WriteUInt16LittleEndian(wave.AsSpan(34), format.ContainerBits);
        BinaryPrimitives.WriteUInt16LittleEndian(wave.AsSpan(36), 22);
        BinaryPrimitives.WriteUInt16LittleEndian(wave.AsSpan(38), format.ValidBits);
        BinaryPrimitives.WriteUInt32LittleEndian(wave.AsSpan(40), 3);
        Convert.FromHexString("0100000000001000800000AA00389B71").CopyTo(wave, 44);
        "data"u8.CopyTo(wave.AsSpan(60)); BinaryPrimitives.WriteUInt32LittleEndian(wave.AsSpan(64), checked((uint)dataBytes));
        double peak = Math.Pow(10, -72.0 / 20);
        int fadeFrames = checked((int)format.SampleRate / 200);
        for (int frame = 0; frame < frames; frame++)
        {
            double envelope = Math.Min(1, Math.Min((double)frame / fadeFrames, (double)(frames - 1 - frame) / fadeFrames));
            double value = peak * envelope * Math.Sin(2 * Math.PI * 500 * frame / format.SampleRate);
            int integer = checked((int)Math.Round(value * ((1L << (format.ValidBits - 1)) - 1))) << (format.ContainerBits - format.ValidBits);
            for (int channel = 0; channel < format.Channels; channel++)
                for (int index = 0; index < sampleBytes; index++)
                    wave[68 + frame * frameBytes + channel * sampleBytes + index] = unchecked((byte)(integer >> (index * 8)));
        }
        return wave;
    }

    private static object Describe(Exception error) => new
    {
        type = error.GetType().FullName, error.Message, hresult = $"0x{error.HResult:X8}",
        causes = error is AggregateException aggregate ? aggregate.InnerExceptions.Select(Describe).ToArray()
            : error.InnerException is { } inner ? new[] { Describe(inner) } : Array.Empty<object>()
    };
    private static void Write(object value, TextWriter? report = null) => (report ?? Console.Out).WriteLine(JsonSerializer.Serialize(value,
        new JsonSerializerOptions { WriteIndented = true, IncludeFields = true, Converters = { new JsonStringEnumConverter() } }));

    private sealed class Observation
    {
        public int SourceReads;
        public int Submissions, RefillSubmissions, SubmittedBytes;
        public int Starts, StartNotifications, Stops, ClientReleases, DeviceReleases;
    }
    private sealed class ObservedDevice(IExclusivePcmDevice device, byte[] source, Observation observation) : IExclusivePcmDevice
    {
        public IExclusivePcmClient Activate() => new ObservedClient(device.Activate(), source, observation);
        public void Dispose() { device.Dispose(); observation.DeviceReleases++; }
    }
    private sealed class ObservedClient(IExclusivePcmClient client, byte[] source, Observation observation) : IExclusivePcmClient
    {
        public int IsExactFormatSupported(ExactPcmFormat format) => client.IsExactFormatSupported(format);
        public int Initialize(ExactPcmFormat format, long bufferDuration100Nanoseconds) => client.Initialize(format, bufferDuration100Nanoseconds);
        public uint GetBufferFrames() => client.GetBufferFrames();
        public int GetStreamLatency(out long latency100Nanoseconds) => client.GetStreamLatency(out latency100Nanoseconds);
        public void Prepare() => client.Prepare();
        public uint GetQueuedFrames() => client.GetQueuedFrames();
        public int GetClockPosition(out ulong position, out ulong frequency) => client.GetClockPosition(out position, out frequency);
        public void Submit(byte[] bytes, int offset, int count, uint frames)
        {
            if (count <= 0 || observation.SubmittedBytes > source.Length - count ||
                !bytes.AsSpan(offset, count).SequenceEqual(source.AsSpan(observation.SubmittedBytes, count)))
                throw new InvalidDataException("Product submission changed or reordered the original PCM source bytes.");
            client.Submit(bytes, offset, count, frames);
            observation.SubmittedBytes += count; observation.Submissions++;
            if (observation.Starts != 0) observation.RefillSubmissions++;
        }
        public void Start() { client.Start(); observation.Starts++; }
        public void WaitForProgress(TimeSpan delay, CancellationToken cancellationToken) => client.WaitForProgress(delay, cancellationToken);
        public void Stop() { client.Stop(); observation.Stops++; }
        public void Dispose() { client.Dispose(); observation.ClientReleases++; }
    }
}
