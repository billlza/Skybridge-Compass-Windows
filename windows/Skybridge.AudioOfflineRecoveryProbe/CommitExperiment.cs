using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Skybridge.WinClient.Services;

namespace Skybridge.AudioOfflineRecoveryProbe;

/// <summary>Native process-interruption checks of the product file committer.
/// All records are synthetic. This is not a second product session store.</summary>
internal static class CommitExperiment
{
    private sealed record Result(string Name, string Observation, int[] ProcessIds, int? NativeError = null);

    internal static void Child(string directory, string operation)
    {
        switch (operation)
        {
            case "before-commit":
            case "after-commit":
                Prepare(directory, "replacement");
                if (operation == "after-commit") Commit(directory);
                WaitAtBarrier("ready");
                return;
            case "hold-destination":
                using (new FileStream(Head(directory), FileMode.Open, FileAccess.Read, FileShare.Read))
                    WaitAtBarrier("ready");
                return;
            case "hold-lock":
                using (new FileStream(LockPath(directory), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                    WaitAtBarrier("ready");
                return;
            case "read-original":
            case "read-replacement":
                var expected = operation[5..];
                RequireValue(Head(directory), expected);
                Console.WriteLine(expected);
                return;
            default: throw new ArgumentException("Unknown native commit experiment operation.");
        }
    }

    internal static async Task RunAsync(string resultDirectory)
    {
        resultDirectory = Path.GetFullPath(resultDirectory);
        if (Directory.Exists(resultDirectory) || File.Exists(resultDirectory))
            throw new IOException("Use a new commit experiment result directory.");
        Directory.CreateDirectory(resultDirectory);
        List<Result> results = [];
        string current = "managed-boundaries";
        string? failure = null;
        try
        {
            foreach (var test in SessionFileCommitTests.Cases)
            {
                current = test.Name;
                await test.Run();
                Record(new(test.Name, "passed on native Windows", [Environment.ProcessId]));
            }
            foreach (var phase in new[] { "before-commit", "after-commit" })
            {
                current = "process-stop-" + phase;
                var directory = NewCase(current);
                Prepare(directory, "original"); Commit(directory);
                int writerId;
                await using (var writer = ChildProcess.Start(directory, phase))
                {
                    writerId = writer.Id;
                    await writer.ExpectAsync("ready");
                    await writer.KillAtBarrierAsync();
                }
                string expected = phase == "before-commit" ? "original" : "replacement";
                await using var reader = ChildProcess.Start(directory, "read-" + expected);
                await reader.ExpectAsync(expected); await reader.RequireSuccessAsync();
                Require(reader.Id != writerId && reader.Id != Environment.ProcessId, "Restart read did not use a separate process.");
                Require(File.Exists(Temporary(directory)) == (phase == "before-commit"), "Unexpected prepared-file state after process stop.");
                Record(new(current, expected + " retained and DPAPI-verified after writer termination", [writerId, reader.Id]));
            }

            current = "destination-sharing-denial-and-release";
            {
                var directory = NewCase(current);
                Prepare(directory, "original"); Commit(directory); Prepare(directory, "replacement");
                await using var holder = ChildProcess.Start(directory, "hold-destination");
                await holder.ExpectAsync("ready");
                IOException? rejected = null;
                try { Commit(directory); }
                catch (IOException error) { rejected = error; }
                if (rejected?.InnerException is not Win32Exception native || native.NativeErrorCode == 0)
                    throw new InvalidOperationException("An occupied destination must report the native commit failure.", rejected);
                RequireValue(Head(directory), "original"); RequireValue(Temporary(directory), "replacement");
                await holder.KillAtBarrierAsync();
                // A distinct experiment attempt after the holder exits. Product
                // commit has no retry or copy/delete compatibility path.
                Commit(directory); RequireValue(Head(directory), "replacement");
                Record(new(current, "prior record and prepared replacement preserved; new attempt succeeds after holder exits",
                    [Environment.ProcessId, holder.Id], native.NativeErrorCode));
            }

            current = "reader-keeps-old-complete-record-across-replacement";
            {
                var directory = NewCase(current); Prepare(directory, "original"); Commit(directory);
                using var reader = new FileStream(Head(directory), FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                Prepare(directory, "replacement"); Commit(directory);
                var bytes = new byte[checked((int)reader.Length)]; reader.ReadExactly(bytes);
                RequireEncryptedValue(bytes, "original"); RequireValue(Head(directory), "replacement");
                Record(new(current, "old open handle and new canonical path each expose one complete authenticated record", [Environment.ProcessId]));
            }

            current = "cross-process-file-lease-released-after-holder-termination";
            {
                var directory = NewCase(current);
                await using var holder = ChildProcess.Start(directory, "hold-lock");
                await holder.ExpectAsync("ready");
                bool denied = false;
                try { using var contender = new FileStream(LockPath(directory), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException) { denied = true; }
                Require(denied, "A second process acquired an occupied FileShare.None lease.");
                await holder.KillAtBarrierAsync();
                using var next = new FileStream(LockPath(directory), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                Record(new(current, "second owner denied while occupied; acquisition succeeds after termination without deleting lock file",
                    [holder.Id, Environment.ProcessId]));
            }
        }
        catch (Exception error) { failure = current + ": " + error; throw; }
        finally
        {
            File.WriteAllBytes(Path.Combine(resultDirectory, "commit-report.json"), JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = 1, kind = "native-protected-file-commit-experiment", succeeded = failure is null,
                runtime = RuntimeInformation.FrameworkDescription, operatingSystem = RuntimeInformation.OSDescription,
                productSource = "windows/Skybridge.WinClient/Services/SessionPersistenceContracts.cs",
                results, failure,
                unverified = new[] { "Power failure and filesystem/controller durability", "Termination inside the native rename call",
                    "Session compare-and-swap, pending revocation and migration", "Protected product audio recovery",
                    "Physical phone-to-computer playback" }
            }, new JsonSerializerOptions { WriteIndented = true }));
        }

        string NewCase(string name) => Directory.CreateDirectory(Path.Combine(resultDirectory, name)).FullName;
        void Record(Result result) { results.Add(result); Console.WriteLine("PASS " + result.Name); }
    }

    private static string Head(string directory) => Path.Combine(directory, "synthetic-record.bin");
    private static string Temporary(string directory) => Path.Combine(directory, ".synthetic-prepared.tmp");
    private static string LockPath(string directory) => Path.Combine(directory, ".synthetic.lock");
    private static byte[] Payload(string value) => Encoding.UTF8.GetBytes(value + ":" + new string(value == "original" ? 'a' : 'b', 16_384));
    private static void Prepare(string directory, string value)
    {
        var plaintext = Payload(value);
        try { SessionFileCommitTests.WritePrepared(Temporary(directory), ProtectedData.Protect(plaintext, null, DataProtectionScope.CurrentUser)); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    private static void Commit(string directory) => AtomicSessionFileCommitter.Instance.Commit(Temporary(directory), Head(directory));
    private static void RequireValue(string path, string value) => RequireEncryptedValue(File.ReadAllBytes(path), value);
    private static void RequireEncryptedValue(byte[] bytes, string value)
    {
        var plaintext = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
        try { Require(plaintext.AsSpan().SequenceEqual(Payload(value)), "The canonical record was incomplete or unexpected."); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    private static void WaitAtBarrier(string message)
    {
        Console.WriteLine(message); Console.Out.Flush();
        if (Console.ReadLine() is null) throw new IOException("The parent closed the experiment before terminating its child.");
        throw new IOException("The experiment child must be terminated at the observed barrier.");
    }
    private static void Require(bool condition, string message)
    { if (!condition) throw new InvalidOperationException(message); }

    private sealed class ChildProcess(Process process) : IAsyncDisposable
    {
        private readonly Task<string> _stderr = process.StandardError.ReadToEndAsync();
        internal int Id { get; } = process.Id;
        internal static ChildProcess Start(string directory, string operation)
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Missing executable.");
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                RedirectStandardInput = true, CreateNoWindow = true
            };
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            start.ArgumentList.Add("--commit-child"); start.ArgumentList.Add(directory); start.ArgumentList.Add(operation);
            return new(Process.Start(start) ?? throw new IOException("Native experiment child did not start."));
        }
        internal async Task ExpectAsync(string expected)
        {
            var observed = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Require(observed == expected, "Native child did not reach the expected barrier: " + observed);
        }
        internal async Task KillAtBarrierAsync()
        {
            Require(!process.HasExited, "Native child exited before the requested interruption.");
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Require(process.ExitCode != 0, "Terminated child reported normal success.");
            await RequireNoExtraOutputAsync();
        }
        internal async Task RequireSuccessAsync()
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Require(process.ExitCode == 0, "Native child failed with exit code " + process.ExitCode);
            await RequireNoExtraOutputAsync();
        }
        private async Task RequireNoExtraOutputAsync()
        {
            var remaining = await process.StandardOutput.ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(10));
            var error = await _stderr.WaitAsync(TimeSpan.FromSeconds(10));
            Require(string.IsNullOrWhiteSpace(remaining) && string.IsNullOrWhiteSpace(error), "Unexpected native child output: " + error);
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                await _stderr.WaitAsync(TimeSpan.FromSeconds(10));
            }
            finally { process.Dispose(); }
        }
    }
}
