using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Skybridge.WinClient.Services;

namespace Skybridge.AudioOfflineRecoveryProbe;

// Links the real SessionStore; no alternate persistence or lock implementation.
// Follow-up probes observe availability only. A failed first save remains failed.
internal static class LeaseTerminationStudy
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(20);
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private sealed record Availability(double MillisecondsAfterExit, bool Opened, SessionStoreFailure? Failure);
    private sealed record Attempt(int Number, string Mode, int Parent, int Child, int ExitCode,
        double FirstWriteMillisecondsAfterExit, string Status, SessionStoreFailure? Failure, SessionStoreFailure? Cleanup,
        RestartManagerObservation.Observation? Owners, Availability[] Availability,
        string? ReadbackStatus, bool? SameRevision, bool? SameLogin);

    internal static void Child(string directory, string mode)
    {
        var store = new SessionStore(directory);
        if (!store.Load().Succeeded) throw new InvalidDataException("The lease child cannot read its synthetic account record.");
        using (var lease = new FileStream(Path.Combine(directory, ".session.lock"), FileMode.Open, FileAccess.ReadWrite,
            mode == "reader" ? FileShare.ReadWrite | FileShare.Delete : FileShare.None))
        {
            Console.WriteLine("READY"); Console.Out.Flush();
            if (Console.ReadLine() != "release") throw new InvalidDataException("The child did not receive its release command.");
        }
    }

    internal static async Task RunAsync(string resultDirectory)
    {
        resultDirectory = Path.GetFullPath(resultDirectory);
        if (Directory.Exists(resultDirectory) || File.Exists(resultDirectory)) throw new IOException("Use a new lease-study directory.");
        Directory.CreateDirectory(resultDirectory);
        List<Attempt> attempts = []; string? failure = null;
        RestartManagerObservation.Observation? calibration = null;
        bool? identifiedKnownHolder = null;
        try
        {
            var calibrationDirectory = Prepare(resultDirectory, "observer-calibration");
            await using (var child = await Holder.Start(calibrationDirectory, "holder"))
            {
                calibration = RestartManagerObservation.Read(Path.Combine(calibrationDirectory, ".session.lock"));
                identifiedKnownHolder = calibration.Error == 0 && calibration.Owners.Any(owner => owner.ProcessId == child.Process.Id);
                await child.ReleaseAsync();
            }
            SaveReport();
            for (int number = 1; number <= 20; number++)
            foreach (string mode in new[] { "abrupt", "graceful" })
            {
                var directory = Prepare(resultDirectory, $"{number:D2}-{mode}");
                var store = new SessionStore(directory); var original = store.Load();
                if (!original.Succeeded || original.Version is null) throw new InvalidDataException("The parent cannot read its synthetic record.");
                await using var child = await Holder.Start(directory, "holder");
                var blocked = store.Save(original.Session!, original.Version, SessionStoreSaveMode.ContinueLogin);
                if (blocked.Status != SessionStoreWriteStatus.IoFailure || blocked.Failure?.Operation != "AcquireLease")
                    throw new InvalidOperationException("The held lease did not exclude a competing writer at the expected boundary.");
                if (mode == "abrupt")
                { child.Process.Kill(entireProcessTree: true); await child.Process.WaitForExitAsync().WaitAsync(Limit); }
                else await child.ReleaseAsync();
                long exited = Stopwatch.GetTimestamp();
                var first = store.Save(original.Session!, original.Version, SessionStoreSaveMode.ContinueLogin);
                double firstAt = Stopwatch.GetElapsedTime(exited).TotalMilliseconds;
                RestartManagerObservation.Observation? owners = null; List<Availability> availability = [];
                SessionStoreLoadResult? readback = null;
                if (!first.Succeeded)
                {
                    owners = RestartManagerObservation.Read(Path.Combine(directory, ".session.lock"));
                    // Fixed, bounded observation points after the failed write; no mutation retry.
                    foreach (int offset in new[] { 0, 10, 50, 100, 250, 500, 1000, 2000 })
                    {
                        double elapsed = Stopwatch.GetElapsedTime(exited).TotalMilliseconds;
                        if (elapsed < offset) await Task.Delay(TimeSpan.FromMilliseconds(offset - elapsed));
                        SessionStoreFailure? error = null;
                        try { using var probe = new FileStream(Path.Combine(directory, ".session.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
                        catch (Exception cause) when (cause is IOException or UnauthorizedAccessException)
                        { error = SessionStoreFailure.From("ObserveLeaseAvailability", cause); }
                        availability.Add(new(Stopwatch.GetElapsedTime(exited).TotalMilliseconds, error is null, error));
                    }
                    readback = store.Load();
                }
                var result = new Attempt(number, mode, Environment.ProcessId, child.Process.Id, child.Process.ExitCode,
                    firstAt, first.Status.ToString(), first.Failure, first.CleanupFailure, owners, availability.ToArray(),
                    readback?.Status.ToString(), readback is null ? null : readback.Version == original.Version,
                    readback is null ? null : readback.LoginId == original.LoginId);
                attempts.Add(result);
                File.WriteAllBytes(Path.Combine(directory, "observation.json"), JsonSerializer.SerializeToUtf8Bytes(result, Json));
                SaveReport();
                Console.WriteLine($"LEASE_STUDY {number} {mode} {first.Status}");
                if (!first.Succeeded) throw new IOException("The first post-exit product write failed; observations were retained without retrying it.");
            }
        }
        catch (Exception error) { failure = error.ToString(); throw; }
        finally { SaveReport(); }
        void SaveReport() => File.WriteAllBytes(Path.Combine(resultDirectory, "lease-study.json"), JsonSerializer.SerializeToUtf8Bytes(new
        {
            kind = "native-product-lease-termination-observation", runtime = Environment.Version.ToString(),
            operatingSystem = Environment.OSVersion.VersionString, protection = "CurrentUser-DPAPI",
            calibration, identifiedKnownHolder, attempts, failure,
            qualification = "isolated storage experiment; no account service, network session or audio output",
            productMutationRetried = false, productPolicyChanged = false
        }, Json));
    }

    private static string Prepare(string root, string name)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root, name)).FullName;
        var authority = SessionAuthority.ForSupabaseProject("https://lease-probe.invalid");
        static string B(object value) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string token = B(new { alg = "EdDSA", typ = "JWT" }) + "." + B(new { iss = authority.Issuer,
            sub = "lease-probe-user", aud = "authenticated", role = "authenticated",
            exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() }) + ".dGVzdA";
        var session = new PersistedSession { SchemaVersion = PersistedSession.CurrentSchemaVersion, Authority = authority,
            Subject = "lease-probe-user", AccessToken = token, RefreshToken = "synthetic-refresh", DisplayName = "Lease probe",
            IssuedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
        var saved = new SessionStore(directory).Save(session, SessionStoreVersion.Missing, SessionStoreSaveMode.NewLogin);
        if (!saved.Succeeded) throw new IOException($"Could not prepare the synthetic account: {saved.Status}; {saved.Failure}.");
        return directory;
    }

    private sealed class Holder(Process process) : IAsyncDisposable
    {
        internal Process Process { get; } = process;
        private readonly Task<string> _errors = process.StandardError.ReadToEndAsync();
        internal static async Task<Holder> Start(string directory, string mode)
        {
            string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Missing executable path.");
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            foreach (string argument in new[] { "--lease-child", directory, mode }) start.ArgumentList.Add(argument);
            var holder = new Holder(Process.Start(start) ?? throw new InvalidOperationException("Lease holder did not start."));
            try
            {
                if (await holder.Process.StandardOutput.ReadLineAsync().WaitAsync(Limit) != "READY")
                    throw new IOException("Lease holder did not establish its barrier: " + await holder._errors.WaitAsync(Limit));
                return holder;
            }
            catch { await holder.DisposeAsync(); throw; }
        }
        internal async Task ReleaseAsync()
        {
            await Process.StandardInput.WriteLineAsync("release"); await Process.StandardInput.FlushAsync();
            await Process.WaitForExitAsync().WaitAsync(Limit);
            if (Process.ExitCode != 0) throw new IOException("Orderly lease-holder release failed: " + await _errors.WaitAsync(Limit));
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!Process.HasExited) Process.Kill(entireProcessTree: true);
                await Process.WaitForExitAsync().WaitAsync(Limit);
                string errors = await _errors.WaitAsync(Limit);
                if (errors.Length != 0) Console.WriteLine("LEASE_CHILD_DIAGNOSTIC " + errors);
            }
            finally { Process.Dispose(); }
        }
    }
}
