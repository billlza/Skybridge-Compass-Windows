namespace Skybridge.WinClient.Services;

internal static class WeatherPresentationPolicy
{
    // -1 means the user's home background, with no weather or wet-glass layer.
    public static int Condition(bool enabled, string? condition) => enabled ? condition?.Trim().ToLowerInvariant() switch
    {
        "clear" or "sunny" or "fair" => 0,
        "cloudy" or "clouds" or "overcast" or "partlycloudy" or "mostlycloudy" => 1,
        "rainy" or "rain" or "drizzle" or "showers" => 2,
        "stormy" or "storm" or "thunderstorm" or "thunder" => 3,
        "snowy" or "snow" or "sleet" or "blizzard" => 4,
        "foggy" or "fog" or "mist" => 5,
        "haze" or "hazy" or "smoke" or "dust" => 6,
        _ => -1
    } : -1;

    public static bool ShouldAnimate(bool enabled, bool visible, bool systemAnimationsEnabled) =>
        enabled && visible && systemAnimationsEnabled;
}
