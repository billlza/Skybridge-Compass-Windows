using Skybridge.WinClient.Services;

internal static class LocationPermissionRequestTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("location permission settings reads never invoke the explicit native request", ReadOnlySettings),
        ("location permission explicit request preserves the actual denied result", ExplicitDenied),
        ("location permission pending request never reports an intent result", Pending),
        ("location permission native failure is propagated without an intent fallback", Failed)
    ];
    private static async Task ReadOnlySettings()
    {
        int requests = 0;
        var client = new SettingsWorkspaceClient(new DisabledSystemPreferencesLauncher(), () => {
            requests++; throw new Exception("Read-only settings requested permission.");
        });
        _ = client.BuildInitialStatus(); _ = client.CanRequestPermission();
        _ = await client.BuildReadOnlySnapshotAsync();
        Require(requests == 0, "Construction or status enumeration requested permission.");
    }
    private static async Task ExplicitDenied()
    {
        int requests = 0; var denied = new SettingsWorkspaceActionResult("Location", "Denied by the system");
        var client = new SettingsWorkspaceClient(new DisabledSystemPreferencesLauncher(), () => {
            requests++; return Task.FromResult(denied);
        });
        var actual = await client.BuildPermissionRequestActionAsync();
        Require(requests == 1 && ReferenceEquals(actual, denied), "Permission result was duplicated or replaced by a successful intent.");
    }
    private static async Task Pending()
    {
        var completion = new TaskCompletionSource<SettingsWorkspaceActionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new SettingsWorkspaceClient(new DisabledSystemPreferencesLauncher(), () => completion.Task);
        var request = client.BuildPermissionRequestActionAsync();
        Require(!request.IsCompleted, "Pending native consent produced a completed intent.");
        var allowed = new SettingsWorkspaceActionResult("Location", "Allowed"); completion.SetResult(allowed);
        Require(ReferenceEquals(await request, allowed), "Permission callback result changed.");
    }
    private static async Task Failed()
    {
        var cause = new InvalidOperationException("Synthetic native permission failure.");
        var client = new SettingsWorkspaceClient(new DisabledSystemPreferencesLauncher(), () => Task.FromException<SettingsWorkspaceActionResult>(cause));
        try { await client.BuildPermissionRequestActionAsync(); }
        catch (InvalidOperationException error) when (ReferenceEquals(error, cause)) { return; }
        throw new Exception("Native permission failure was hidden by an intent result.");
    }
    private static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
