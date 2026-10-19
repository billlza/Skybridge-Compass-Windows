using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.WinClient.Services.Audio;

internal static class NativePacingStudy
{
    private const int SamplesPerRun = 512;
    private const long BufferBudgetTicks = TimeSpan.TicksPerMillisecond * 200;
    private sealed record Measurement(string Mode, int Run, int ThreadId, long[] ElapsedTicks,
        long? MaximumTicks, long? P50Ticks, long? P99Ticks, int Over200Milliseconds, bool PacingReleased);

    internal static bool Run(string directory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native pacing requires Windows.");
        directory = Path.GetFullPath(directory);
        if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("Use a new pacing result directory.");
        Directory.CreateDirectory(directory);
        var measurements = new List<Measurement>();
        var checks = new List<string>();
        string? failure = null;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        try
        {
            Lifecycle(checks, deadline.Token);
            // ABBA order keeps both paths represented before and after the
            // product registration. It does not make a finite sample a bound.
            foreach (var (mode, run) in new[] { ("previous-sleep", 1), ("windows-product", 1),
                         ("windows-product", 2), ("previous-sleep", 2) })
            {
                var samples = new long[SamplesPerRun];
                int completedCount = 0;
                WindowsAudioRenderPacing? pacing = null;
                bool released = mode == "previous-sleep";
                Exception? bodyFailure = null;
                try
                {
                    if (mode == "windows-product") { pacing = new(); pacing.Start(); }
                    for (int i = 0; i < samples.Length; i++)
                    {
                        deadline.Token.ThrowIfCancellationRequested();
                        var started = Stopwatch.GetTimestamp();
                        if (pacing is not null) pacing.Wait(TimeSpan.FromMilliseconds(1), deadline.Token);
                        else Thread.Sleep(1);
                        samples[i] = Stopwatch.GetElapsedTime(started).Ticks;
                        completedCount++;
                    }
                }
                catch (Exception error) { bodyFailure = error; throw; }
                finally
                {
                    Exception? cleanupFailure = null;
                    if (pacing is not null)
                    {
                        try { pacing.Dispose(); released = true; }
                        catch (Exception cleanup) { cleanupFailure = cleanup; }
                    }
                    var completed = samples[..completedCount];
                    var sorted = completed.Order().ToArray();
                    measurements.Add(new(mode, run, Environment.CurrentManagedThreadId, completed,
                        sorted.Length == 0 ? null : sorted[^1], Percentile(sorted, 0.50), Percentile(sorted, 0.99),
                        completed.Count(value => value >= BufferBudgetTicks), released));
                    if (cleanupFailure is not null)
                    {
                        if (bodyFailure is not null) throw new AggregateException(bodyFailure, cleanupFailure);
                        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(cleanupFailure).Throw();
                    }
                }
            }
            return measurements.All(value => value.Mode != "windows-product" || value.Over200Milliseconds == 0);
        }
        catch (Exception error) { failure = error.ToString(); throw; }
        finally
        {
            var assembly = typeof(NativePacingStudy).Assembly.Location;
            File.WriteAllBytes(Path.Combine(directory, "pacing-report.json"), JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = 1, scope = "native-pacing-comparison-without-audio-output", failure,
                experimentCompleted = failure is null && measurements.Count == 4 && measurements.All(value => value.ElapsedTicks.Length == SamplesPerRun),
                productionSamplesWithin200Milliseconds = failure is null && measurements.Count == 4 &&
                    measurements.Where(value => value.Mode == "windows-product").All(value => value.Over200Milliseconds == 0),
                lifecycleChecks = checks, measurements, requestedTicks = TimeSpan.TicksPerMillisecond,
                runtime = RuntimeInformation.FrameworkDescription, operatingSystem = RuntimeInformation.OSDescription,
                processors = Environment.ProcessorCount, assemblySha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(assembly))),
                unverified = new[] { "Physical WASAPI playback", "Phone transport", "Long-run continuity or a scheduling upper bound",
                    "Reproduction of the prior 258 ms descheduling cause", "Physical Realtek full-padding stall" }
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    private static void Lifecycle(List<string> checks, CancellationToken token)
    {
        using var pacing = new WindowsAudioRenderPacing();
        Reject<ArgumentOutOfRangeException>(() => pacing.Wait(TimeSpan.Zero, token)); checks.Add("zero delay rejected");
        Reject<ArgumentOutOfRangeException>(() => pacing.Wait(TimeSpan.FromMilliseconds(6), token)); checks.Add("out-of-range delay rejected");
        pacing.Wait(TimeSpan.FromMilliseconds(1), token); checks.Add("prepared wait before Start completes");
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        try { pacing.Wait(TimeSpan.FromMilliseconds(1), canceled.Token); throw new InvalidOperationException("Canceled wait succeeded."); }
        catch (OperationCanceledException error) when (error.CancellationToken == canceled.Token)
        { checks.Add("cancellation retains its exact token"); }
        pacing.Start(); checks.Add("Audio MMCSS registration succeeds");
        Reject<InvalidOperationException>(pacing.Start); checks.Add("repeated registration rejected");
        WrongThread(() => pacing.Wait(TimeSpan.FromMilliseconds(1), token)); checks.Add("cross-thread wait rejected");
        WrongThread(pacing.Dispose); checks.Add("cross-thread disposal rejected");
        pacing.Wait(TimeSpan.FromMilliseconds(1), token); checks.Add("owner remains usable after rejected cross-thread operations");
        pacing.Dispose(); checks.Add("owner releases timer and MMCSS");
        pacing.Dispose(); checks.Add("successful release is idempotent");
        Reject<ObjectDisposedException>(() => pacing.Wait(TimeSpan.FromMilliseconds(1), token)); checks.Add("wait after disposal rejected");
        Reject<ObjectDisposedException>(pacing.Start); checks.Add("registration after disposal rejected");
    }
    private static void WrongThread(Action operation)
    {
        Exception? failure = null;
        var thread = new Thread(() => { try { operation(); } catch (Exception error) { failure = error; } })
        { IsBackground = true, Name = "audio-pacing-owner-check" };
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(5))) throw new TimeoutException("Pacing owner check did not finish.");
        if (failure is not InvalidOperationException) throw new InvalidOperationException("Wrong-thread operation was not rejected.", failure);
    }
    private static void Reject<T>(Action operation) where T : Exception
    {
        try { operation(); } catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name + ".");
    }
    private static long? Percentile(long[] sorted, double fraction) => sorted.Length == 0 ? null : sorted[(int)Math.Ceiling(sorted.Length * fraction) - 1];
}
