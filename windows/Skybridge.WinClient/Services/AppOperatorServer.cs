using System.IO.Pipes;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

namespace Skybridge.WinClient.Services;

internal sealed class AppOperatorException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

internal sealed record AppOperatorRequest(string Id, string Method, JsonElement Parameters);

/// <summary>One bounded local command at a time, owned by the visible application.</summary>
internal sealed class AppOperatorServer : IAsyncDisposable
{
    internal const string Protocol = "skybridge-app-control/1";
    internal const int MaxMessageBytes = 64 * 1024;
    private readonly NamedPipeServerStream _pipe;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Func<AppOperatorRequest, CancellationToken, Task<JsonObject>> _execute;
    private readonly Action<Exception> _reportFailure;
    private readonly Task _loop;

    internal AppOperatorServer(Func<AppOperatorRequest, CancellationToken, Task<JsonObject>> execute,
        Action<Exception> reportFailure, string? pipeName = null)
    {
        _execute = execute;
        _reportFailure = reportFailure;
        _pipe = CreatePipe(pipeName ?? $"SkyBridge.OperatorControl.v1.{Environment.ProcessId}");
        _loop = RunAsync();
    }

    private static NamedPipeServerStream CreatePipe(string name)
    {
        if (!OperatingSystem.IsWindows())
            return new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance,
                MaxMessageBytes, MaxMessageBytes);
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new IOException("The local operator pipe requires a user identity.");
        var security = new PipeSecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        var descriptor = GCHandle.Alloc(security.GetSecurityDescriptorBinaryForm(), GCHandleType.Pinned);
        try
        {
            var attributes = new PipeSecurityAttributes { Length = Marshal.SizeOf<PipeSecurityAttributes>(),
                SecurityDescriptor = descriptor.AddrOfPinnedObject(), InheritHandle = false };
            // Explicit local-only mode: a same-account SMB login must not become an
            // operator client. The managed PipeOptions API has no reject-remote flag.
            const uint duplexOverlappedFirst = 0x3 | 0x40000000 | 0x00080000;
            const uint rejectRemoteClients = 0x8;
            var handle = CreateNamedPipeW(@"\\.\pipe\" + name, duplexOverlappedFirst,
                rejectRemoteClients, 1, MaxMessageBytes, MaxMessageBytes, 0, ref attributes);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new Win32Exception(error, "The local operator pipe could not be created.");
            }
            try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); }
            catch { handle.Dispose(); throw; }
        }
        finally { descriptor.Free(); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PipeSecurityAttributes
    {
        internal int Length;
        internal nint SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode,
        uint maxInstances, uint outBufferSize, uint inBufferSize, uint defaultTimeout, ref PipeSecurityAttributes attributes);

    internal static AppOperatorRequest Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0 || bytes.Length > MaxMessageBytes)
            throw new AppOperatorException("invalid_request", "The request exceeds the local command limit.");
        using var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        RequireProperties(root, "protocol", "id", "method", "params");
        if (root.GetProperty("protocol").GetString() != Protocol
            || !Guid.TryParseExact(root.GetProperty("id").GetString(), "D", out _)
            || root.GetProperty("method").ValueKind != JsonValueKind.String
            || root.GetProperty("params").ValueKind != JsonValueKind.Object)
            throw new AppOperatorException("invalid_request", "The local command protocol or request ID is invalid.");
        return new(root.GetProperty("id").GetString()!, root.GetProperty("method").GetString()!,
            root.GetProperty("params").Clone());
    }

    internal static void RequireProperties(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new AppOperatorException("invalid_parameters", "Expected a parameter object.");
        var actual = value.EnumerateObject().Select(property => property.Name).ToArray();
        if (actual.Length != names.Length || actual.Distinct(StringComparer.Ordinal).Count() != actual.Length
            || actual.Any(name => !names.Contains(name, StringComparer.Ordinal)))
            throw new AppOperatorException("invalid_parameters", "Unknown, duplicate or missing command parameters.");
    }

    internal static async Task<JsonObject> DispatchAsync(Func<Action, bool> enqueue,
        Func<CancellationToken, Task<JsonObject>> execute, CancellationToken token)
    {
        var completion = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        int state = 0; // queued, executing, or cancelled before execution
        using var registration = token.Register(() =>
        {
            if (Interlocked.CompareExchange(ref state, 2, 0) == 0) completion.TrySetCanceled(token);
        });
        if (!enqueue(async () =>
        {
            if (Interlocked.CompareExchange(ref state, 1, 0) != 0) return;
            try { completion.TrySetResult(await execute(token)); }
            catch (Exception error) { completion.TrySetException(error); }
        })) throw new AppOperatorException("app_dispatch_unavailable", "The application window is unavailable.");
        // Cancellation can retire a queued callback. Once execution starts, retain
        // ownership until the real operation and its cancellation cleanup finish.
        return await completion.Task.ConfigureAwait(false);
    }

    internal static async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken token)
    {
        using var bytes = new MemoryStream();
        var buffer = new byte[1024];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            if (read == 0) throw new AppOperatorException("invalid_request", "The command ended before its newline.");
            int newline = Array.IndexOf(buffer, (byte)'\n', 0, read);
            int count = newline < 0 ? read : newline;
            if (bytes.Length + count > MaxMessageBytes)
                throw new AppOperatorException("invalid_request", "The request exceeds the local command limit.");
            bytes.Write(buffer, 0, count);
            if (newline >= 0)
            {
                if (newline != read - 1)
                    throw new AppOperatorException("invalid_request", "Only one local command is accepted per connection.");
                return bytes.ToArray();
            }
        }
    }

    private async Task RunAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                await _pipe.WaitForConnectionAsync(_lifetime.Token).ConfigureAwait(false);
                try { await ServeAsync().ConfigureAwait(false); }
                catch (IOException error) { _reportFailure(error); }
                catch (OperationCanceledException error) when (!_lifetime.IsCancellationRequested) { _reportFailure(error); }
                finally { if (_pipe.IsConnected) _pipe.Disconnect(); }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception error) { _reportFailure(error); }
    }

    private async Task ServeAsync()
    {
        using var requestLifetime = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        requestLifetime.CancelAfter(TimeSpan.FromSeconds(30));
        string? id = null;
        JsonObject response;
        try
        {
            var request = Parse(await ReadMessageAsync(_pipe, requestLifetime.Token).ConfigureAwait(false));
            id = request.Id;
            var result = await _execute(request, requestLifetime.Token).ConfigureAwait(false);
            response = new() { ["protocol"] = Protocol, ["id"] = id, ["success"] = true, ["result"] = result };
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            if (_lifetime.IsCancellationRequested) return;
            var known = error as AppOperatorException;
            var code = known?.Code ?? (error is OperationCanceledException ? "operation_timeout" :
                error is JsonException or InvalidOperationException or KeyNotFoundException ? "invalid_request" : "app_operation_failed");
            if (known is null && code == "app_operation_failed") _reportFailure(error);
            response = new() { ["protocol"] = Protocol, ["id"] = id, ["success"] = false,
                ["error"] = new JsonObject { ["code"] = code,
                    ["message"] = known?.Message ?? "The command was not confirmed. Read app status before retrying.", ["retryable"] = false } };
        }
        byte[] output = Encoding.UTF8.GetBytes(response.ToJsonString() + "\n");
        if (output.Length > MaxMessageBytes)
            throw new IOException("The application command result exceeds the local command limit.");
        using var writeLifetime = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        writeLifetime.CancelAfter(TimeSpan.FromSeconds(2));
        await _pipe.WriteAsync(output, writeLifetime.Token).ConfigureAwait(false);
        await _pipe.FlushAsync(writeLifetime.Token).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _lifetime.CancelAsync().ConfigureAwait(false);
        await _loop.ConfigureAwait(false);
        _pipe.Dispose();
        _lifetime.Dispose();
    }
}
