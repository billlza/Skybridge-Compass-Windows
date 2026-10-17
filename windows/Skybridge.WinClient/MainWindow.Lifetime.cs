using System;
using System.ComponentModel;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Skybridge.WinClient.Services;
using Windows.UI.ViewManagement;
using Windows.System.Power;

namespace Skybridge.WinClient;

public sealed partial class MainWindow
{
    private WindowsTrayIcon? _trayIcon;
    private readonly WindowLifetimeController _windowLifetime;
    private readonly UISettings _uiSettings = new();

    private void ConfigureWindowLifetime()
    {
        ViewModel.Settings.PropertyChanged += OnLifetimeSettingsChanged;
        AppWindow.Changed += OnLifetimeWindowChanged;
        RootShell.Loaded += OnLifetimeLoaded;
        _uiSettings.AnimationsEnabledChanged += OnSystemAnimationChanged;
        PowerManager.EnergySaverStatusChanged += OnEnergySaverChanged;
        UpdateWeatherAnimationEnvironment();
        QueueLifetimeAction(UpdateTrayPreference);
    }

    private bool EnsureTrayIcon()
    {
        _trayIcon ??= new WindowsTrayIcon(WinRT.Interop.WindowNative.GetWindowHandle(this),
            System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "SkyBridgeCompass.ico"),
            Title, RemoteControlText("TrayOpen"), RemoteControlText("TrayExit"),
            () => QueueLifetimeAction(RestoreMainWindow),
            () => QueueLifetimeAction(RequestApplicationExit),
            error => QueueLifetimeAction(() => ReportTrayFailure(error)),
            ending => _windowLifetime.SessionEnding = ending);
        return _trayIcon.EnsureVisible();
    }

    private void QueueLifetimeAction(Action action)
    {
        if (!DispatcherQueue.TryEnqueue(() => { if (!_hostShutdownComplete) action(); }))
            WindowsRuntimeLog.Write(WindowsLogLevel.Error, "tray", "The window dispatcher rejected a notification area action.");
    }

    private void RestoreMainWindow()
    {
        AppWindow.Show();
        if (AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized } presenter)
            presenter.Restore();
        Activate();
        UpdateWeatherAnimationEnvironment();
    }

    private async void RequestApplicationExit()
    {
        _windowLifetime.RequestExit();
        await ShutdownAsync();
    }

    private void ReportTrayFailure(Exception error)
    {
        WindowsRuntimeLog.Write(WindowsLogLevel.Error, "tray", error.ToString());
        RestoreMainWindow();
        _notifications.Add(RemoteControlText("TrayUnavailableTitle"), RemoteControlText("TrayUnavailableDetail"), "\uE7BA");
        if (RootShell.IsLoaded) ShowNotifications();
    }

    private void UpdateTrayPreference()
    {
        if (ViewModel.Settings.CloseToTray)
        {
            try
            {
                if (!EnsureTrayIcon()) throw new InvalidOperationException("The notification area icon could not be registered.");
            }
            catch (Exception error) { ReportTrayFailure(error); }
        }
        else
        {
            if (_trayIcon is not null && !AppWindow.IsVisible) RestoreMainWindow();
            _trayIcon?.Remove();
        }
    }

    private void OnLifetimeSettingsChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (string.IsNullOrEmpty(args.PropertyName) || args.PropertyName == nameof(ViewModel.Settings.CloseToTray))
            UpdateTrayPreference();
        if (string.IsNullOrEmpty(args.PropertyName) || args.PropertyName == nameof(ViewModel.Settings.PerformanceMode))
            UpdateWeatherAnimationEnvironment();
    }

    private void OnLifetimeLoaded(object sender, RoutedEventArgs args) => UpdateWeatherAnimationEnvironment();
    private void OnLifetimeWindowChanged(AppWindow sender, AppWindowChangedEventArgs args) => UpdateWeatherAnimationEnvironment();
    private void OnSystemAnimationChanged(UISettings sender, object args) => QueueLifetimeAction(UpdateWeatherAnimationEnvironment);
    private void OnEnergySaverChanged(object? sender, object args) => QueueLifetimeAction(UpdateWeatherAnimationEnvironment);

    private void UpdateWeatherAnimationEnvironment()
    {
        bool visible = AppWindow.IsVisible &&
            AppWindow.Presenter is not OverlappedPresenter { State: OverlappedPresenterState.Minimized };
        int framesPerSecond = PowerManager.EnergySaverStatus == EnergySaverStatus.On || ViewModel.Settings.PerformanceMode == "powerSaving"
            ? 24 : ViewModel.Settings.PerformanceMode == "extreme" ? 60 : 30;
        WeatherBackdrop.SetAnimationEnvironment(visible, _uiSettings.AnimationsEnabled, framesPerSecond);
    }

    private void DisposeWindowLifetime()
    {
        ViewModel.Settings.PropertyChanged -= OnLifetimeSettingsChanged;
        AppWindow.Changed -= OnLifetimeWindowChanged;
        RootShell.Loaded -= OnLifetimeLoaded;
        _uiSettings.AnimationsEnabledChanged -= OnSystemAnimationChanged;
        PowerManager.EnergySaverStatusChanged -= OnEnergySaverChanged;
        _trayIcon?.Dispose();
        _trayIcon = null;
    }
}
