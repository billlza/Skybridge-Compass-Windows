using System.Globalization;
using System.Net;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.RemoteControl;

internal static class WindowsLanConnectionInfoTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("Windows direct info matches an independently encoded Android-compatible Unicode vector", Golden),
        ("Windows direct info rejects unspecified local-only multicast and unsupported IP routes", InvalidEndpoints),
        ("Windows direct info rejects Unicode replacement and invisible boundary whitespace", InvalidText),
        ("Windows direct info keeps invariant port spelling and exact public identity", CultureIndependent),
        ("connection publication revalidates authority before admitting a copy", RevokedAuthority),
        ("connection publication rejects a replaced listener even at the same endpoint", ReplacedOwner),
        ("connection publication freezes its route and rejects port or address drift", ChangedEndpoint),
        ("connection publication copies only its bounded public hint while owner is current", LiveCopy),
        ("connection publication preserves clipboard failures without reporting success", CopyFailure),
        ("connection publication retains the actual asynchronous copy completion", CopyCompletion),
        ("stopped real MAIN listener cannot supply a connection publication", StoppedListener)
    ];
    private static RemoteControlPairingMaterial Identity(string name = "书房 Windows 🧑‍💻") =>
        RemoteControlPairingMaterial.CreateProtocolIdentity("id:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", name,
            Enumerable.Repeat((byte)0x33, 1952).ToArray());
    private static IPEndPoint Endpoint() => new(IPAddress.Parse("192.168.1.60"), 50978);
    private const string Expected = "skybridge://lan/v1/MTkyLjE2OC4xLjYw/50978/aWQ6YmJiYmJiYmItYmJiYi1iYmJiLWJiYmItYmJiYmJiYmJiYmJi/5547af701878021fe78fca9909c769e40ec23b143b6b400a7432c8e1bbd50469/5Lmm5oi_IFdpbmRvd3Mg8J-nkeKAjfCfkrs/windows";
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T error) { return error; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
    private static Task Golden()
    {
        // Fixed Python struct/hash/base64 vector, independently consumed by Android.
        Require(WindowsLanConnectionInfo.Encode(Endpoint(), Identity()) == Expected, "Shared format changed.");
        return Task.CompletedTask;
    }
    private static async Task InvalidEndpoints()
    {
        foreach (var address in new[] { "0.0.0.0", "0.1.2.3", "127.0.0.1", "169.254.2.3", "224.0.0.1", "255.255.255.255", "::1", "2001:db8::1", "::ffff:192.168.1.60" })
            await Throws<InvalidDataException>(() => { WindowsLanConnectionInfo.Encode(new(IPAddress.Parse(address), 50978), Identity()); return Task.CompletedTask; });
        await Throws<InvalidDataException>(() => { WindowsLanConnectionInfo.Encode(new(Endpoint().Address, 0), Identity()); return Task.CompletedTask; });
    }
    private static async Task InvalidText()
    {
        foreach (var name in new[] { "\u200bWindows", "Windows\ufeff", "Win\ud800dows", "Win\udc00dows" })
            await Throws<InvalidDataException>(() => { WindowsLanConnectionInfo.Encode(Endpoint(), Identity(name)); return Task.CompletedTask; });
        var longest = new string('界', 128);
        Require(WindowsLanConnectionInfo.Encode(Endpoint(), Identity(longest)).Length < 2048, "Valid maximum name failed.");
    }
    private static Task CultureIndependent()
    {
        var prior = CultureInfo.CurrentCulture;
        try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA"); return Golden(); }
        finally { CultureInfo.CurrentCulture = prior; }
    }
    private static async Task RevokedAuthority()
    {
        bool current = true; int reads = 0, copies = 0;
        var expected = new InvalidOperationException("account ended");
        var publication = new LanConnectionInfoPublication(Identity(), () => { reads++; if (!current) throw expected; return Endpoint(); });
        current = false;
        Require(ReferenceEquals(await Throws<InvalidOperationException>(() => publication.CopyAsync(_ => { copies++; return Task.CompletedTask; })), expected)
            && reads == 2 && copies == 0, "Revoked account reached clipboard or lost its failure.");
        await Throws<InvalidOperationException>(() => { _ = new LanConnectionInfoPublication(Identity(), () => throw expected); return Task.CompletedTask; });
    }
    private static async Task ReplacedOwner()
    {
        var captured = new object(); object current = captured; int copies = 0;
        var publication = new LanConnectionInfoPublication(Identity(), () =>
        { if (!ReferenceEquals(captured, current)) throw new InvalidOperationException("listener replaced"); return Endpoint(); });
        current = new object();
        await Throws<InvalidOperationException>(() => publication.CopyAsync(_ => { copies++; return Task.CompletedTask; }));
        Require(copies == 0, "Same-address replacement reused an old identity hint.");
    }
    private static async Task ChangedEndpoint()
    {
        foreach (bool addressChanges in new[] { false, true })
        {
            var route = Endpoint(); int copies = 0;
            var publication = new LanConnectionInfoPublication(Identity(), () => route);
            if (addressChanges) route.Address = IPAddress.Parse("192.168.1.61"); else route.Port++;
            await Throws<InvalidOperationException>(() => publication.CopyAsync(_ => { copies++; return Task.CompletedTask; }));
            Require(copies == 0, "Mutable route changed the frozen publication.");
        }
    }
    private static async Task LiveCopy()
    {
        int reads = 0, copies = 0;
        var publication = new LanConnectionInfoPublication(Identity(), () => { reads++; return Endpoint(); });
        await publication.CopyAsync(text => { Require(text == Expected, "Copy included stale or nonpublic material."); copies++; return Task.CompletedTask; });
        Require(reads == 2 && copies == 1, "Copy did not recheck the actual route.");
    }
    private static async Task CopyFailure()
    {
        var publication = new LanConnectionInfoPublication(Identity(), Endpoint);
        var expected = new IOException("clipboard unavailable");
        Require(ReferenceEquals(await Throws<IOException>(() => publication.CopyAsync(_ => Task.FromException(expected))), expected), "Copy failure was hidden.");
    }
    private static async Task CopyCompletion()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var publication = new LanConnectionInfoPublication(Identity(), Endpoint);
        var copying = publication.CopyAsync(_ => completion.Task);
        Require(!copying.IsCompleted, "A pending copy reported completion.");
        completion.SetResult(); await copying;
    }
    private static async Task StoppedListener()
    {
        await using var listener = new LanProductControlListener((_, _) => Task.CompletedTask, () => true);
        listener.Start(IPAddress.Loopback, CancellationToken.None);
        // Local-only addresses remain rejected even when there is a real socket.
        await Throws<InvalidDataException>(() => { _ = new LanConnectionInfoPublication(Identity(), () => (IPEndPoint)listener.RequireLiveListener().LocalEndpoint); return Task.CompletedTask; });
        await listener.StopAsync();
        await Throws<InvalidOperationException>(() => { _ = new LanConnectionInfoPublication(Identity(), () => (IPEndPoint)listener.RequireLiveListener().LocalEndpoint); return Task.CompletedTask; });
    }
}
