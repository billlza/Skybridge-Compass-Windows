using Microsoft.Windows.ApplicationModel.Resources;
using Windows.Devices.Geolocation;
using Windows.Security.Authorization.AppCapabilityAccess;

namespace Skybridge.WinClient.Services;

internal static class WindowsLocationPermission
{
    // Unlike RequestAccessAsync, CheckAccess is guaranteed not to prompt.
    // https://learn.microsoft.com/uwp/api/windows.security.authorization.appcapabilityaccess.appcapabilityaccessstatus
    internal static AppCapabilityAccessStatus CheckAccess() => AppCapability.Create("location").CheckAccess();

    internal static string Describe(AppCapabilityAccessStatus status) => Text(status switch
    {
        AppCapabilityAccessStatus.Allowed => "LocationPermissionAllowed",
        AppCapabilityAccessStatus.DeniedByUser => "LocationPermissionDeniedByUser",
        AppCapabilityAccessStatus.DeniedBySystem => "LocationPermissionDeniedBySystem",
        AppCapabilityAccessStatus.UserPromptRequired => "LocationPermissionNotRequested",
        AppCapabilityAccessStatus.NotDeclaredByApp => "LocationPermissionUnavailable",
        _ => throw new InvalidDataException("Unknown Windows location permission state.")
    });

    // Wired only to the existing explicit Settings permission command. The
    // command keeps the foreground UI context required by Geolocator.
    internal static async Task<SettingsWorkspaceActionResult> RequestAsync()
    {
        var access = await Geolocator.RequestAccessAsync();
        string message = Text(access switch
        {
            GeolocationAccessStatus.Allowed => "LocationPermissionAllowed",
            GeolocationAccessStatus.Denied => "LocationPermissionDenied",
            GeolocationAccessStatus.Unspecified => "LocationPermissionNotRequested",
            _ => throw new InvalidDataException("Unknown Windows location permission result.")
        });
        return new(Text("LocationPermissionTitle"), message);
    }

    internal static string Text(string key)
    {
        var value = new ResourceLoader().GetString(key);
        return !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"Missing location permission text: {key}.");
    }
}
