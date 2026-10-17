using Skybridge.WinClient.Services;

internal static class WindowLifetimeTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        ("close to tray is opt-in, persists, and leaves the weather setting unchanged", PersistenceAsync),
        ("hide requires a working tray and exit bypasses hide", CloseAsync),
        ("weather toggles restore home and restart motion without replacing the selected weather", WeatherAsync),
        ("native notification icon uses the Windows x64 ABI", NativeLayoutAsync)
    ];

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static Task PersistenceAsync()
    {
        string directory = Path.Combine(Path.GetTempPath(), "skybridge-lifetime-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "settings.json"), "{\"SchemaVersion\":1}");
            var store = new SettingsStore(directory);
            using (var service = new SettingsService(store))
            {
                Check(!service.CloseToTray, "Existing settings must preserve close-to-exit.");
                bool weather = service.EnableRealTimeWeather;
                service.CloseToTray = true;
                Check(service.EnableRealTimeWeather == weather, "Tray choice changed weather consent.");
                Check(store.Save(service.Snapshot).Succeeded, "Tray setting could not be saved.");
            }
            using var restored = new SettingsService(store);
            Check(restored.CloseToTray, "Tray preference was lost after reload.");
            restored.CloseToTray = false;
        }
        finally { Directory.Delete(directory, recursive: true); }
        return Task.CompletedTask;
    }

    private static Task CloseAsync()
    {
        var calls = new List<string>();
        bool available = true;
        var controller = new WindowLifetimeController(() => { calls.Add("tray"); return available; }, () => calls.Add("hide"));
        Check(!controller.HandleClose(false) && calls.Count == 0, "Default close should proceed to shutdown.");
        Check(controller.HandleClose(true) && calls.SequenceEqual(["tray", "hide"]), "Hide happened before a verified tray icon.");
        calls.Clear(); available = false;
        try { controller.HandleClose(true); throw new Exception("Unavailable tray incorrectly hid the window."); }
        catch (InvalidOperationException) { Check(calls.SequenceEqual(["tray"]), "A failed tray hid the window."); }
        calls.Clear(); controller.RequestExit();
        Check(!controller.HandleClose(true) && calls.Count == 0, "Tray Exit must not hide or depend on Explorer.");
        controller.CancelExit(); controller.SessionEnding = true;
        Check(!controller.HandleClose(true) && calls.Count == 0, "Logoff must not be trapped in the tray.");
        controller.SessionEnding = false; available = true;
        Check(controller.HandleClose(true), "Canceled logoff must restore the user's close preference.");
        return Task.CompletedTask;
    }

    private static Task WeatherAsync()
    {
        foreach (var condition in new[] { "Clear", "Cloudy", "Rainy", "Stormy", "Snowy", "Foggy", "Haze" })
        {
            int before = WeatherPresentationPolicy.Condition(true, condition);
            Check(before >= 0, "Enabled weather did not resolve its rendering mode.");
            Check(WeatherPresentationPolicy.Condition(false, condition) == -1, "Disabled weather retained its last frame.");
            Check(WeatherPresentationPolicy.Condition(true, condition) == before, "Re-enabling weather did not restore its mode.");
        }
        Check(WeatherPresentationPolicy.Condition(true, "Unknown") == -1, "Unavailable data must not invent weather.");
        Check(WeatherPresentationPolicy.ShouldAnimate(true, true, true), "Enabled, visible weather must advance automatically.");
        Check(!WeatherPresentationPolicy.ShouldAnimate(false, true, true), "Disabled weather is still ticking.");
        Check(!WeatherPresentationPolicy.ShouldAnimate(true, false, true), "Hidden windows are still ticking.");
        Check(!WeatherPresentationPolicy.ShouldAnimate(true, true, false), "System reduced motion was ignored.");
        return Task.CompletedTask;
    }

    private static Task NativeLayoutAsync()
    {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("This contract targets the shipped Windows x64 ABI.");
        var data = typeof(WindowsTrayIcon).GetNestedType("NotifyIconData", System.Reflection.BindingFlags.NonPublic)!;
        Check(System.Runtime.InteropServices.Marshal.SizeOf(data) == 976, "NOTIFYICONDATAW size does not match the x64 shell ABI.");
        Check(System.Runtime.InteropServices.Marshal.OffsetOf(data, "Tip").ToInt32() == 40, "Tray tooltip offset is incorrect.");
        Check(System.Runtime.InteropServices.Marshal.OffsetOf(data, "Version").ToInt32() == 816, "Tray callback version offset is incorrect.");
        return Task.CompletedTask;
    }
}
