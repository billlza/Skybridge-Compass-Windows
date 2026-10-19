using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using Skybridge.AudioOfflineRecoveryProbe;

[assembly: SupportedOSPlatform("windows")]

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("This experiment requires native Windows DPAPI, CryptProtectMemory and QPC.");

if (args is ["--lease-child", var leaseDirectory, var leaseMode])
{
    LeaseTerminationStudy.Child(leaseDirectory, leaseMode);
    return;
}
if (args is ["--lease-study", var leaseResultDirectory])
{
    await LeaseTerminationStudy.RunAsync(leaseResultDirectory);
    return;
}

if (args is ["--commit-child", var commitDirectory, var commitOperation])
{
    CommitExperiment.Child(commitDirectory, commitOperation);
    return;
}
if (args is ["--commit-run", var commitResultDirectory])
{
    await CommitExperiment.RunAsync(commitResultDirectory);
    return;
}
if (args is ["--observe-rename-sharing", var sharingResultDirectory])
{
    CommitExperiment.ObserveSharing(sharingResultDirectory);
    return;
}
if (args is ["--write", var writeFolder, var writeCase])
{
    Probe.Write(writeFolder, writeCase);
    Console.WriteLine(JsonSerializer.Serialize(new Reply("written", Environment.ProcessId, null)));
    return;
}
if (args is ["--read", var readFolder, var readCase])
{
    Console.WriteLine(JsonSerializer.Serialize(Probe.Read(readFolder, readCase)));
    return;
}
if (args is not ["--run", var resultFolder])
    throw new ArgumentException("Usage: AudioOfflineRecoveryProbe --run <new result folder>");

await Probe.RunAsync(resultFolder);

internal sealed record Anchor(long Wall, long Continuous)
{
    internal static Anchor Now()
    {
        if (!Stopwatch.IsHighResolution)
            throw new PlatformNotSupportedException("The experiment requires Windows QPC.");
        return new(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            checked((long)((Int128)Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency)));
    }
}

internal sealed record Checkpoint(int Version, Guid LoginId, Guid EvidenceId, string Authority, string Subject,
    string Tenant, string Local, string Peer, Anchor Issued, Anchor Expires, LogonContinuity.Seal Continuity);
internal sealed record Reply(string Status, int ProcessId, CheckpointIdentity? Identity,
    string? Detail = null, int? NativeError = null);
internal sealed record CheckpointIdentity(Guid LoginId, Guid EvidenceId, Anchor Issued, Anchor Expires);
internal sealed record CaseResult(string Name, string Expected, string Observed, int WriterProcess, int ReaderProcess,
    bool PreservedOriginalIdentityAndDeadlines, string ClockSource, string? Detail, int? NativeError);
internal sealed record ProbeReport(int Version, string Kind, bool Succeeded, string Runtime, string OperatingSystem,
    CaseResult[] Cases, string[] Unverified, string? Failure);
internal sealed class CheckpointRejectedException(string reason) : IOException(reason)
{
    internal string Reason { get; } = reason;
}

internal static class Probe
{
    private const long Lifetime = 60_000;
    private const int MaximumBytes = 64 * 1024;
    private const string Authority = "https://offline-audio-probe.invalid/auth/v1";
    private const string Subject = "synthetic-subject";
    private const string Tenant = "synthetic-tenant";
    private const string Local = "synthetic-local-identity";
    private const string Peer = "synthetic-peer-identity";

    internal static void Write(string directory, string variant)
    {
        Directory.CreateDirectory(directory);
        var issued = Anchor.Now();
        var expires = new Anchor(checked(issued.Wall + Lifetime), checked(issued.Continuous + Lifetime));
        var seal = LogonContinuity.Create(variant == "process-bound" ? 0u : LogonContinuity.SameLogon);
        if (variant == "tampered-nonce") seal.ProtectedNonce[0] ^= 1;
        if (variant == "tampered-commitment") seal.NonceDigest[0] ^= 1;
        if (variant == "malformed-seal") seal = seal with { ProtectedNonce = new byte[31] };
        var checkpoint = new Checkpoint(1, Guid.NewGuid(), Guid.NewGuid(), Authority, Subject, Tenant, Local, Peer,
            issued, variant == "excessive-lifetime" ? expires with { Wall = issued.Wall + 3_600_001 } : expires, seal);
        if (variant == "wrong-version") checkpoint = checkpoint with { Version = 2 };
        if (variant == "empty-identity") checkpoint = checkpoint with { EvidenceId = Guid.Empty };
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(checkpoint);
        byte[] encrypted;
        try { encrypted = ProtectedData.Protect(plaintext, null, DataProtectionScope.CurrentUser); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        if (variant == "tampered-dpapi") encrypted[encrypted.Length / 2] ^= 1;
        if (variant == "oversized") encrypted = new byte[MaximumBytes + 1];
        using (var file = new FileStream(Path.Combine(directory, "checkpoint.bin"), FileMode.CreateNew, FileAccess.Write,
                   FileShare.None, 4096, FileOptions.WriteThrough))
        {
            file.Write(encrypted);
            file.Flush(flushToDisk: true);
        }
        File.WriteAllBytes(Path.Combine(directory, "identity.json"), JsonSerializer.SerializeToUtf8Bytes(
            new CheckpointIdentity(checkpoint.LoginId, checkpoint.EvidenceId, issued, checkpoint.Expires)));
    }

    internal static Reply Read(string directory, string variant)
    {
        var expected = JsonSerializer.Deserialize<CheckpointIdentity>(File.ReadAllBytes(Path.Combine(directory, "identity.json")))
            ?? throw new InvalidDataException("Missing experiment identity.");
        byte[]? plaintext = null;
        string phase = "record";
        try
        {
            using var file = new FileStream(Path.Combine(directory, "checkpoint.bin"), FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length is <= 0 or > MaximumBytes) throw new CheckpointRejectedException("capacity");
            var encrypted = new byte[checked((int)file.Length)];
            file.ReadExactly(encrypted);
            if (file.ReadByte() != -1) throw new CheckpointRejectedException("capacity");
            plaintext = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
            var checkpoint = JsonSerializer.Deserialize<Checkpoint>(plaintext)
                ?? throw new InvalidDataException("Missing checkpoint.");
            ValidateShape(checkpoint);
            var expectedLogin = variant == "wrong-login" ? Guid.NewGuid() : expected.LoginId;
            if (checkpoint.LoginId != expectedLogin) throw new CheckpointRejectedException("login-changed");
            if (checkpoint.Authority != (variant == "wrong-authority" ? Authority + "/changed" : Authority) ||
                checkpoint.Subject != Subject || checkpoint.Tenant != Tenant)
                throw new CheckpointRejectedException("account-changed");
            if (checkpoint.Local != Local || checkpoint.Peer != (variant == "wrong-peer" ? Peer + "-changed" : Peer))
                throw new CheckpointRejectedException("identity-changed");
            phase = "logon";
            LogonContinuity.RequireCurrent(checkpoint.Continuity);
            phase = "clock";
            var now = variant switch
            {
                // These are deterministic policy counterexamples, explicitly
                // separated from the real QPC process-restart check in reports.
                "expired-wall" => new(checkpoint.Expires.Wall, checkpoint.Issued.Continuous),
                "expired-continuous" => new(checkpoint.Issued.Wall, checkpoint.Expires.Continuous),
                "rollback-wall" => new(checkpoint.Issued.Wall - 1, checkpoint.Issued.Continuous),
                "rollback-continuous" => new(checkpoint.Issued.Wall, checkpoint.Issued.Continuous - 1),
                _ => Anchor.Now()
            };
            if (now.Wall < checkpoint.Issued.Wall || now.Continuous < checkpoint.Issued.Continuous)
                throw new CheckpointRejectedException("clock-changed");
            if (now.Wall >= checkpoint.Expires.Wall || now.Continuous >= checkpoint.Expires.Continuous)
                throw new CheckpointRejectedException("expired");
            return new("accepted", Environment.ProcessId,
                new(checkpoint.LoginId, checkpoint.EvidenceId, checkpoint.Issued, checkpoint.Expires));
        }
        catch (CheckpointRejectedException failure) { return new(failure.Reason, Environment.ProcessId, null); }
        catch (LogonContinuityException) { return new("logon-unavailable", Environment.ProcessId, null, "nonce-commitment-mismatch"); }
        catch (Win32Exception failure) when (phase == "logon")
        { return new("logon-unavailable", Environment.ProcessId, null, "native-memory-unprotect-failed", failure.NativeErrorCode); }
        catch (CryptographicException failure) when (phase == "record")
        { return new("record-integrity-failed", Environment.ProcessId, null, "dpapi-unprotect-failed", failure.HResult); }
        catch (InvalidDataException) { return new("invalid-checkpoint", Environment.ProcessId, null); }
        finally { if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static void ValidateShape(Checkpoint value)
    {
        if (value.Version != 1 || value.LoginId == Guid.Empty || value.EvidenceId == Guid.Empty ||
            value.Issued is null || value.Expires is null || value.Continuity is null ||
            value.Issued.Wall <= 0 || value.Issued.Continuous < 0)
            throw new InvalidDataException("Invalid checkpoint shape.");
        decimal wallLifetime = (decimal)value.Expires.Wall - value.Issued.Wall;
        decimal continuousLifetime = (decimal)value.Expires.Continuous - value.Issued.Continuous;
        if (wallLifetime is <= 0 or > 3_600_000 || continuousLifetime != wallLifetime)
            throw new InvalidDataException("Invalid original lifetime.");
    }

    internal static async Task RunAsync(string resultDirectory)
    {
        resultDirectory = Path.GetFullPath(resultDirectory);
        if (Directory.Exists(resultDirectory) || File.Exists(resultDirectory))
            throw new IOException("Use a new experiment result directory.");
        Directory.CreateDirectory(resultDirectory);
        var cases = new (string Name, string Expected)[] {
            ("same-logon", "accepted"), ("process-bound", "logon-unavailable"),
            ("tampered-nonce", "logon-unavailable"), ("tampered-commitment", "logon-unavailable"),
            ("tampered-dpapi", "record-integrity-failed"), ("wrong-login", "login-changed"),
            ("wrong-authority", "account-changed"), ("wrong-peer", "identity-changed"),
            ("expired-wall", "expired"), ("expired-continuous", "expired"),
            ("rollback-wall", "clock-changed"), ("rollback-continuous", "clock-changed"),
            ("oversized", "capacity"), ("excessive-lifetime", "invalid-checkpoint"),
            ("malformed-seal", "invalid-checkpoint"), ("wrong-version", "invalid-checkpoint"),
            ("empty-identity", "invalid-checkpoint")
        };
        List<CaseResult> results = [];
        string? failureMessage = null;
        try
        {
            foreach (var item in cases)
            {
                var folder = Path.Combine(resultDirectory, item.Name);
                // The writer must exit before the reader starts. This exercises
                // app-process restart, not two calls sharing process-local state.
                var writer = await ChildAsync("--write", folder, item.Name);
                if (writer.Status != "written") throw new InvalidDataException("Writer did not finish.");
                var reader = await ChildAsync("--read", folder, item.Name);
                var original = JsonSerializer.Deserialize<CheckpointIdentity>(File.ReadAllBytes(Path.Combine(folder, "identity.json")))
                    ?? throw new InvalidDataException("Missing original identity.");
                bool preserved = reader.Status == "accepted" && reader.Identity == original;
                var clockSource = item.Name.StartsWith("expired-", StringComparison.Ordinal) || item.Name.StartsWith("rollback-", StringComparison.Ordinal)
                    ? "controlled-policy-counterexample" : "Windows-QPC-and-UTC";
                results.Add(new(item.Name, item.Expected, reader.Status, writer.ProcessId, reader.ProcessId, preserved,
                    clockSource, reader.Detail, reader.NativeError));
                if (reader.Status != item.Expected || (reader.Status == "accepted" && !preserved) ||
                    writer.ProcessId == reader.ProcessId || reader.ProcessId == Environment.ProcessId)
                    throw new InvalidOperationException($"Case {item.Name}: expected {item.Expected}, observed {reader.Status}.");
                Console.WriteLine($"PASS {item.Name}: {reader.Status}");
            }
        }
        catch (Exception failure)
        {
            failureMessage = failure.ToString();
            throw;
        }
        finally
        {
            var report = new ProbeReport(1, "isolated-windows-audio-offline-continuity", failureMessage is null,
                System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                System.Runtime.InteropServices.RuntimeInformation.OSDescription, results.ToArray(),
                ["Different Windows user or logon session", "OS restart, logout, sleep and hibernation transitions",
                 "Atomic account/checkpoint migration and stale-write rejection", "Product offline startup and carrier integration",
                 "Real account authorization, phone transport and physical audio playback"], failureMessage);
            File.WriteAllBytes(Path.Combine(resultDirectory, "report.json"), JsonSerializer.SerializeToUtf8Bytes(report,
                new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    private static async Task<Reply> ChildAsync(string operation, string directory, string variant)
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Missing process executable.");
        var start = new ProcessStartInfo(executable) {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
        };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        start.ArgumentList.Add(operation); start.ArgumentList.Add(directory); start.ArgumentList.Add(variant);
        using var process = Process.Start(start) ?? throw new IOException("Child process did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            ProcessTerminationBarrier.Require(process, TimeSpan.FromSeconds(5));
            await Task.WhenAll(stdout, stderr);
            throw new TimeoutException("Native child experiment exceeded 15 seconds.");
        }
        ProcessTerminationBarrier.Require(process, TimeSpan.FromSeconds(5));
        var output = await stdout; var error = await stderr;
        if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(error))
            throw new InvalidOperationException($"Native child failed ({process.ExitCode}): {error}");
        return JsonSerializer.Deserialize<Reply>(output) ?? throw new InvalidDataException("Child result is missing.");
    }
}
