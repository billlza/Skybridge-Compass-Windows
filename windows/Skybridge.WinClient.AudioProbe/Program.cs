using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Skybridge.WinClient.Services.Audio;

[assembly: SupportedOSPlatform("windows")]

// Isolated, opt-in native output diagnosis. This is not an account/session receiver
// and never supplies evidence of transport, source-file decoding or hardware fidelity.
Console.OutputEncoding = new UTF8Encoding(false);
var phase = "arguments";
var trace = new NativeOutputTrace();
try
{
    if (args is ["--pacing-study", var pacingDirectory])
    {
        phase = "pacing-study";
        bool withinObservedBudget = NativePacingStudy.Run(pacingDirectory);
        Write(new { schemaVersion = 1, status = withinObservedBudget ? "study-completed" : "observed-budget-exceeded",
            phase, scope = "native-pacing-without-audio-output", report = Path.Combine(Path.GetFullPath(pacingDirectory), "pacing-report.json") });
        return withinObservedBudget ? 0 : 1;
    }
    if (args is not (["--list"] or ["--probe", _] or ["--render-quiet-test", _, _]))
        throw new ArgumentException("Use --list, --probe <endpoint-id>, --render-quiet-test <endpoint-id> <format-name>, or --pacing-study <new-result-directory>.");
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The probe must run on Windows.");
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    phase = "enumerate";
    var endpoints = WindowsExclusivePcmDevice.ReadOutputs(deadline.Token);
    object observation;
    if (args[0] == "--list")
    {
        observation = endpoints.Select(endpoint => new { endpoint.EndpointId, endpoint.DisplayName, endpoint.IsNameMissing }).ToArray();
    }
    else
    {
        // Explicit selection only; never choose the default or the first output.
        var selected = endpoints.SingleOrDefault(endpoint => endpoint.EndpointId == args[1])
            ?? throw new ArgumentException("The exact selected endpoint is not in the current active render catalog.");
        var formats = Formats();
        phase = "format-support";
        if (args[0] == "--probe")
        {
            observation = Probe(selected.EndpointId, formats, deadline.Token);
        }
        else
        {
            if (!formats.TryGetValue(args[2], out var format))
                throw new ArgumentException("Unknown format name; use the names returned by --probe.");
            phase = "render-quiet-test";
            observation = Render(selected.EndpointId, args[2], format, deadline.Token, trace);
        }
    }
    Write(new { schemaVersion = 1, status = "completed", phase, command = args[0],
        os = RuntimeInformation.OSDescription, processArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
        observation, trace, scope = "native-output-component", accountAndTransport = "not-tested", hardwareSampleIntegrity = "not-measured" });
    return 0;
}
catch (Exception error)
{
    Write(new { schemaVersion = 1, status = "failed", phase, error = Describe(error), trace,
        scope = "native-output-component", accountAndTransport = "not-tested", hardwareSampleIntegrity = "not-measured" });
    return 1;
}

static Dictionary<string, ExactPcmFormat> Formats() => new(StringComparer.Ordinal)
{
    ["44100-s16"] = new(44100, 2, 16, 16, false, 3),
    ["48000-s16"] = new(48000, 2, 16, 16, false, 3),
    ["48000-s24"] = new(48000, 2, 24, 24, false, 3),
    ["48000-s24-in-s32"] = new(48000, 2, 32, 24, false, 3),
    ["48000-f32"] = new(48000, 2, 32, 32, true, 3),
    ["96000-s24"] = new(96000, 2, 24, 24, false, 3),
    ["192000-s24"] = new(192000, 2, 24, 24, false, 3)
};

[SupportedOSPlatform("windows")]
static object Probe(string endpointId, Dictionary<string, ExactPcmFormat> formats, CancellationToken token)
{
    var observations = new List<object>();
    var device = WindowsExclusivePcmDevice.Open(endpointId);
    return WithOwner(device, () =>
    {
        var client = device.Activate();
        return WithOwner(client, () =>
        {
            foreach (var (name, format) in formats)
            {
                token.ThrowIfCancellationRequested();
                int result = client.IsExactFormatSupported(format);
                // Only this documented negative result is a successful support observation.
                // Busy devices, invalid COM calls and driver failures are not "unsupported".
                if (result != 0 && result != unchecked((int)0x88890008))
                    throw new COMException($"Unexpected exclusive format-query result for {name}.", result);
                observations.Add(new { name, format, hresult = $"0x{result:X8}", exactExclusiveSupport = result == 0 });
            }
            return new { endpointId, formats = observations, initialized = false, started = false };
        });
    });
}

[SupportedOSPlatform("windows")]
static object Render(string endpointId, string name, ExactPcmFormat format, CancellationToken token, NativeOutputTrace trace)
{
    // One 100 ms synthesized source fits wholly into the product's requested 200 ms
    // buffer. No alternate pump, silence padding, conversion or fallback is involved.
    byte[] source = QuietSource(format);
    uint frames = checked((uint)(source.Length / format.BytesPerFrame));
    token.ThrowIfCancellationRequested();
    var device = new ObservedDevice(WindowsExclusivePcmDevice.Open(endpointId), trace);
    var output = ExclusivePcmOutput.Open(device, format, format.SampleRate / 5);
    return WithOwner(output, () =>
    {
        uint capacity = output.BufferFrames;
        long latency = output.ReportedLatency100Nanoseconds;
        token.ThrowIfCancellationRequested();
        output.Submit(source, 0, source.Length);
        output.FinishInput(frames);
        output.Start();
        var receipt = output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(5), token, token.ThrowIfCancellationRequested);
        if (receipt.SourceFrames != frames || receipt.Tail is null || output.State != ExclusivePcmOutputState.Completed)
            throw new InvalidDataException("Native output did not return the exact nonempty completion receipt.");
        return new { endpointId, name, format, inputFrames = frames, inputBytes = source.Length,
            inputSha256 = Convert.ToHexStringLower(SHA256.HashData(source)), requestedPeakDbfs = -72,
            requestedBufferFrames = format.SampleRate / 5, nativeBufferFrames = capacity,
            reportedLatency100Nanoseconds = latency, state = output.State.ToString(), receipt };
    });
}

static T WithOwner<T>(IDisposable owner, Func<T> observe)
{
    Exception? primary = null;
    try { return observe(); }
    catch (Exception error) { primary = error; throw; }
    finally
    {
        try { owner.Dispose(); }
        catch (Exception cleanup)
        {
            if (primary is not null) throw new AggregateException("Native observation and resource release both failed.", primary, cleanup);
            throw;
        }
    }
}

static byte[] QuietSource(ExactPcmFormat format)
{
    int frames = checked((int)format.SampleRate / 10);
    int sampleBytes = format.ContainerBits / 8;
    var bytes = new byte[checked(frames * format.BytesPerFrame)];
    double peak = Math.Pow(10, -72.0 / 20);
    int fadeFrames = checked((int)format.SampleRate / 200);
    for (int frame = 0; frame < frames; frame++)
    {
        double envelope = Math.Min(1, Math.Min((double)frame / fadeFrames, (double)(frames - 1 - frame) / fadeFrames));
        double value = peak * envelope * Math.Sin(2 * Math.PI * 500 * frame / format.SampleRate);
        for (int channel = 0; channel < format.Channels; channel++)
        {
            var sample = bytes.AsSpan(frame * format.BytesPerFrame + channel * sampleBytes, sampleBytes);
            if (format.FloatingPoint) BinaryPrimitives.WriteSingleLittleEndian(sample, (float)value);
            else
            {
                int integer = checked((int)Math.Round(value * ((1L << (format.ValidBits - 1)) - 1))) << (format.ContainerBits - format.ValidBits);
                for (int index = 0; index < sampleBytes; index++) sample[index] = unchecked((byte)(integer >> (index * 8)));
            }
        }
    }
    return bytes;
}

static object Describe(Exception error) => new
{
    type = error.GetType().FullName, error.Message, hresult = $"0x{error.HResult:X8}",
    causes = error is AggregateException aggregate ? aggregate.InnerExceptions.Select(Describe).ToArray()
        : error.InnerException is { } inner ? new[] { Describe(inner) } : Array.Empty<object>()
};

static void Write(object value) => Console.WriteLine(JsonSerializer.Serialize(value,
    new JsonSerializerOptions { WriteIndented = true, Converters = { new JsonStringEnumConverter() } }));

// Observe the existing native boundary without changing its calls, return values,
// timing budget or cleanup ownership. A bounded log explicitly reports truncation.
internal sealed class NativeOutputTrace
{
    private readonly long _started = Stopwatch.GetTimestamp();
    public List<object> Events { get; } = [];
    public int OmittedEvents { get; private set; }
    internal void Add(string operation, object? value = null)
    {
        if (Events.Count >= 4096) { OmittedEvents++; return; }
        Events.Add(new { elapsedMilliseconds = Stopwatch.GetElapsedTime(_started).TotalMilliseconds, operation, value });
    }
}

internal sealed class ObservedDevice(IExclusivePcmDevice device, NativeOutputTrace trace) : IExclusivePcmDevice
{
    public IExclusivePcmClient Activate()
    {
        var client = device.Activate(); trace.Add("activate"); return new ObservedClient(client, trace);
    }
    public void Dispose() { device.Dispose(); trace.Add("device-disposed"); }
}

internal sealed class ObservedClient(IExclusivePcmClient client, NativeOutputTrace trace) : IExclusivePcmClient
{
    public int IsExactFormatSupported(ExactPcmFormat format)
    {
        int result = client.IsExactFormatSupported(format); trace.Add("exact-format", new { result }); return result;
    }
    public int Initialize(ExactPcmFormat format, long bufferDuration100Nanoseconds)
    {
        int result = client.Initialize(format, bufferDuration100Nanoseconds);
        trace.Add("initialize", new { result, bufferDuration100Nanoseconds }); return result;
    }
    public uint GetBufferFrames()
    {
        uint frames = client.GetBufferFrames(); trace.Add("capacity", new { frames }); return frames;
    }
    public int GetStreamLatency(out long latency100Nanoseconds)
    {
        int result = client.GetStreamLatency(out latency100Nanoseconds);
        trace.Add("latency", new { result, latency100Nanoseconds }); return result;
    }
    public void Prepare() { client.Prepare(); trace.Add("prepared"); }
    public uint GetQueuedFrames()
    {
        uint frames = client.GetQueuedFrames(); trace.Add("padding", new { frames }); return frames;
    }
    public int GetClockPosition(out ulong position, out ulong frequency)
    {
        int result = client.GetClockPosition(out position, out frequency);
        trace.Add("clock", new { result, position, frequency }); return result;
    }
    public void Submit(byte[] bytes, int offset, int count, uint frames)
    {
        client.Submit(bytes, offset, count, frames); trace.Add("submitted", new { count, frames });
    }
    public void Start() { client.Start(); trace.Add("started"); }
    public void WaitForProgress(TimeSpan delay, CancellationToken cancellationToken) => client.WaitForProgress(delay, cancellationToken);
    public void Stop() { client.Stop(); trace.Add("stopped"); }
    public void Dispose() { client.Dispose(); trace.Add("client-disposed"); }
}
