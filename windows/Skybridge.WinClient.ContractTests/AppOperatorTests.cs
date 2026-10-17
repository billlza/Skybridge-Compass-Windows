using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Skybridge.WinClient.Services;

internal static class AppOperatorTests
{
    internal static IEnumerable<(string Name, Func<Task> Run)> Cases =>
    [
        ("app operator rejects malformed and duplicate command envelopes", RejectEnvelopesAsync),
        ("app operator bounds framing and requires a complete newline", FramingAsync),
        ("app settings require independent persisted readback", SettingsReadbackAsync),
        ("app pipe handles an invalid request before a valid request", PipeRecoveryAsync),
        ("queued operator cancellation prevents late mutations", QueuedCancellationAsync),
        ("started operator retains ownership until cancellation cleanup finishes", ActiveCancellationAsync),
        ("app shutdown waits for the executing command cleanup", ShutdownWaitsAsync)
    ];

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static Task RejectEnvelopesAsync()
    {
        string id = Guid.NewGuid().ToString();
        string valid = $$$"""{"protocol":"skybridge-app-control/1","id":"{{{id}}}","method":"app.status","params":{}}""";
        Check(AppOperatorServer.Parse(Encoding.UTF8.GetBytes(valid)).Id == id, "Valid command did not parse.");
        foreach (string invalid in new[] { valid.Replace("/1", "/2"), valid.Replace(id, "invalid"),
            valid.Replace("\"params\":{}", "\"params\":{},\"params\":{}"),
            valid.Replace("\"params\":{}", "\"params\":{},\"unknown\":true"),
            valid.Replace("\"params\":{}", "\"params\":null"), "[]" })
        {
            bool rejected = false;
            try { AppOperatorServer.Parse(Encoding.UTF8.GetBytes(invalid)); }
            catch (Exception error) when (error is AppOperatorException or JsonException or InvalidOperationException) { rejected = true; }
            Check(rejected, "Malformed envelope was accepted.");
        }
        using var duplicate = JsonDocument.Parse("{\"generation\":1,\"generation\":2}");
        bool duplicateRejected = false;
        try { AppOperatorServer.RequireProperties(duplicate.RootElement, "generation"); }
        catch (AppOperatorException) { duplicateRejected = true; }
        Check(duplicateRejected, "Duplicate mutation parameters were accepted.");
        return Task.CompletedTask;
    }

    private static async Task FramingAsync()
    {
        foreach (byte[] bytes in new[] { Encoding.UTF8.GetBytes("{}"), Encoding.UTF8.GetBytes("{}\n{}\n"),
            Encoding.UTF8.GetBytes(new string('x', AppOperatorServer.MaxMessageBytes + 1) + "\n") })
        {
            bool rejected = false;
            try { await AppOperatorServer.ReadMessageAsync(new MemoryStream(bytes), CancellationToken.None); }
            catch (AppOperatorException) { rejected = true; }
            Check(rejected, "Incomplete, multiple or oversized command was accepted.");
        }
        byte[] valid = await AppOperatorServer.ReadMessageAsync(new MemoryStream("{}\n"u8.ToArray()), CancellationToken.None);
        Check(Encoding.UTF8.GetString(valid) == "{}", "Valid framing changed the payload.");
    }

    private sealed class EchoOnlyStore : ISettingsStore
    {
        internal bool FailSave;
        internal bool Untrusted;
        internal int Writes;
        public SettingsStoreLoadResult Load() => Untrusted
            ? SettingsStoreLoadResult.InvalidJson(new SkyBridgeSettings())
            : SettingsStoreLoadResult.Loaded(new SkyBridgeSettings { AppearanceMode = "dark" });
        public SettingsStoreWriteResult Save(SkyBridgeSettings settings)
        {
            Writes++;
            return FailSave ? SettingsStoreWriteResult.IoFailure("test_write_failure") : SettingsStoreWriteResult.Saved();
        }
        public SettingsStoreWriteResult Reset() => throw new NotSupportedException();
        public SettingsStoreWriteResult ExportTo(string path, SkyBridgeSettings settings) => throw new NotSupportedException();
        public SettingsStoreLoadResult ImportFrom(string path) => throw new NotSupportedException();
    }

    private static Task SettingsReadbackAsync()
    {
        var store = new EchoOnlyStore();
        using var settings = new SettingsService(store);
        settings.AppearanceMode = "light";
        Check(settings.PersistAndReadBackAppearanceMode() == "dark", "The write echo replaced the independent stored value.");
        store.FailSave = true;
        bool failed = false;
        try { settings.PersistAndReadBackAppearanceMode(); }
        catch (IOException) { failed = true; }
        Check(failed, "A failed save was reported as persisted.");
        var untrustedStore = new EchoOnlyStore { Untrusted = true };
        using var untrusted = new SettingsService(untrustedStore);
        bool refused = false;
        try { untrusted.PersistAndReadBackAppearanceMode(); }
        catch (IOException) { refused = true; }
        Check(refused && untrustedStore.Writes == 0, "The operator save overwrote untrusted stored settings.");
        return Task.CompletedTask;
    }

    private static async Task PipeRecoveryAsync()
    {
        string name = "sbop-" + Guid.NewGuid().ToString("N");
        var failures = new List<Exception>();
        int calls = 0;
        await using var server = new AppOperatorServer((_, _) => { Interlocked.Increment(ref calls); return Task.FromResult(new JsonObject { ["read"] = true }); },
            failures.Add, name);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        async Task<JsonObject> Call(string input)
        {
            using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await client.ConnectAsync(timeout.Token);
            await client.WriteAsync(Encoding.UTF8.GetBytes(input + "\n"), timeout.Token);
            var bytes = await AppOperatorServer.ReadMessageAsync(client, timeout.Token);
            return JsonNode.Parse(bytes)!.AsObject();
        }
        var rejected = await Call("{}");
        Check(rejected["success"]!.GetValue<bool>() == false && calls == 0, "Invalid envelope reached the handler.");
        string id = Guid.NewGuid().ToString();
        var accepted = await Call($$$"""{"protocol":"skybridge-app-control/1","id":"{{{id}}}","method":"app.status","params":{}}""");
        Check(accepted["success"]!.GetValue<bool>() && accepted["id"]!.GetValue<string>() == id && calls == 1,
            "A malformed client killed the local command server.");
        Check(failures.Count == 0, "The server reported unexpected transport failure.");
    }

    private static async Task QueuedCancellationAsync()
    {
        Action? queued = null;
        int writes = 0;
        using var cancellation = new CancellationTokenSource();
        var operation = AppOperatorServer.DispatchAsync(action => { queued = action; return true; },
            _ => { writes++; return Task.FromResult(new JsonObject()); }, cancellation.Token);
        await cancellation.CancelAsync();
        bool cancelled = false;
        try { await operation; } catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled, "Queued command did not cancel.");
        queued!();
        Check(writes == 0, "The cancelled queued command performed a late mutation.");
    }

    private static async Task ActiveCancellationAsync()
    {
        using var cancellation = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cleanup = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cleaning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var operation = AppOperatorServer.DispatchAsync(action => { action(); return true; }, async token =>
        {
            started.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            catch (OperationCanceledException) { cleaning.SetResult(); await cleanup.Task; throw; }
            return new JsonObject();
        }, cancellation.Token);
        await started.Task;
        await cancellation.CancelAsync();
        await cleaning.Task;
        Check(!operation.IsCompleted, "Timeout released command ownership before real cleanup completed.");
        cleanup.SetResult();
        bool cancelled = false;
        try { await operation; } catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled, "Cancelled active command reported success.");
    }
    private static async Task ShutdownWaitsAsync()
    {
        string name = "sbop-" + Guid.NewGuid().ToString("N");
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cleaning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new AppOperatorServer(async (_, token) =>
        {
            started.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            catch (OperationCanceledException) { cleaning.SetResult(); await finish.Task; throw; }
            return new JsonObject();
        }, error => throw new InvalidOperationException("Unexpected pipe failure", error), name);
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await client.ConnectAsync(timeout.Token);
        string request = JsonSerializer.Serialize(new { protocol = AppOperatorServer.Protocol,
            id = Guid.NewGuid().ToString(), method = "app.status", @params = new { } });
        await client.WriteAsync(Encoding.UTF8.GetBytes(request + "\n"), timeout.Token);
        await started.Task.WaitAsync(timeout.Token);
        var dispose = server.DisposeAsync().AsTask();
        await cleaning.Task.WaitAsync(timeout.Token);
        Check(!dispose.IsCompleted, "App shutdown abandoned an executing command.");
        finish.SetResult();
        await dispose.WaitAsync(timeout.Token);
    }

}
