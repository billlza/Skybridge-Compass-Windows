using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Skybridge.WinClient.Services;
using Windows.Security.Authorization.AppCapabilityAccess;

namespace Skybridge.WinClient.Settings;

// Reading status never requests access. The existing Settings permission command
// is the explicit request path; AccessChanged refreshes this read-only row.
public sealed partial class SettingsPermissionsView : UserControl
{
    private AppCapability? _locationCapability;

    public SettingsPermissionsView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_locationCapability is not null) return;
        try
        {
            var capability = AppCapability.Create("location");
            capability.AccessChanged += OnLocationAccessChanged;
            _locationCapability = capability;
            RefreshLocationAccess();
        }
        catch (Exception error) { ShowReadFailure(error); }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_locationCapability is not { } capability) return;
        _locationCapability = null;
        capability.AccessChanged -= OnLocationAccessChanged;
    }

    private void OnLocationAccessChanged(AppCapability sender, AppCapabilityAccessChangedEventArgs args)
    {
        if (!DispatcherQueue.TryEnqueue(() =>
        {
            if (ReferenceEquals(sender, _locationCapability)) RefreshLocationAccess();
        })) WindowsRuntimeLog.Write(WindowsLogLevel.Debug, "LocationPermission", "Permission view dispatcher closed.");
    }

    private void RefreshLocationAccess()
    {
        if (LocationAccessValue is null || _locationCapability is null) return;
        try { LocationAccessValue.Text = WindowsLocationPermission.Describe(_locationCapability.CheckAccess()); }
        catch (Exception error) { ShowReadFailure(error); }
    }

    private void ShowReadFailure(Exception error)
    {
        LocationAccessValue.Text = WindowsLocationPermission.Text("LocationPermissionReadFailed");
        WindowsRuntimeLog.Write(WindowsLogLevel.Warning, "LocationPermission", error.GetType().Name);
    }
}
