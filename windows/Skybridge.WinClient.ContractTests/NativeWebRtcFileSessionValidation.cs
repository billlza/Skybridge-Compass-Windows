using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using Skybridge.WinClient.Services;

internal static class NativeWebRtcFileSessionValidation
{
    internal static async Task RunAsync(string helper)
    {
        if (!File.Exists(helper)) throw new FileNotFoundException("The built product WebRTC helper is required.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = timeout.Token;
        var root = Directory.CreateTempSubdirectory("skybridge-webrtc-test-").FullName;
        try
        {
            var offer = Path.Combine(root, "offer.json"); var answer = Path.Combine(root, "answer.json");
            await using var left = Start(helper, "offer", offer, answer, root);
            await using var right = Start(helper, "answer", offer, answer, root);
            var ports = await Task.WhenAll(left.ReadPortAsync(token), right.ReadPortAsync(token));
            await using var a = new WebRtcProductControlPlaneClient(ports[0], ipcAuthToken: left.IpcSecret);
            await using var b = new WebRtcProductControlPlaneClient(ports[1], ipcAuthToken: right.IpcSecret);
            await Task.WhenAll(a.StartAsync(token), b.StartAsync(token));
            await WindowsWebRtcFileSessionTests.TransferOverHelpers(a, b);
        }
        finally { Directory.Delete(root, true); }
    }

    private static Child Start(string path, string role, string offer, string answer, string root)
    {
        var options = new ProcessStartInfo(Path.GetFullPath(path)) {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            WorkingDirectory = root, CreateNoWindow = true
        };
        foreach (string name in options.Environment.Keys.ToArray())
            if (!new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "USERPROFILE", "HOME",
                    "LOCALAPPDATA", "APPDATA", "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64" }.Contains(name, StringComparer.OrdinalIgnoreCase))
                options.Environment.Remove(name);
        const string envName = "SKYBRIDGE_TEST_PROCESS_IPC_KEY";
        var key = RandomNumberGenerator.GetBytes(32);
        options.Environment[envName] = Convert.ToBase64String(key);
        foreach (var argument in new[] { "--mode", "product-control-" + role, "--ipc-port", "0",
            "--offer-out", offer, "--offer-in", offer, "--answer-out", answer, "--answer-in", answer,
            "--ice-include-all-interfaces", "true", "--ipc-auth-token-env", envName })
            options.ArgumentList.Add(argument);
        try { return new(Process.Start(options) ?? throw new IOException("Could not launch the built helper."), key); }
        catch { CryptographicOperations.ZeroMemory(key); throw; }
        finally { options.Environment.Remove(envName); }
    }

    private sealed class Child : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly byte[] _key;
        private readonly Task _errors;
        private Task? _stdout;
        internal Child(Process process, byte[] key)
        {
            _process = process; _key = key;
            _errors = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        }
        internal ReadOnlyMemory<byte> IpcSecret => _key;
        internal async Task<int> ReadPortAsync(CancellationToken token)
        {
            const string marker = "SKYBRIDGE_PRODUCT_CONTROL_PORT=";
            while (await _process.StandardOutput.ReadLineAsync(token) is { } line)
            {
                if (!line.StartsWith(marker, StringComparison.Ordinal)) continue;
                if (!int.TryParse(line.AsSpan(marker.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
                    port is < 1 or > 65535) throw new InvalidDataException("Helper returned an invalid IPC port.");
                _stdout = _process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
                return port;
            }
            throw new IOException("The helper exited before its secured IPC listener became ready.");
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!_process.HasExited) _process.Kill(entireProcessTree: true);
                await _process.WaitForExitAsync();
                await Task.WhenAll(_errors, _stdout ?? Task.CompletedTask);
            }
            finally { _process.Dispose(); CryptographicOperations.ZeroMemory(_key); }
        }
    }
}
