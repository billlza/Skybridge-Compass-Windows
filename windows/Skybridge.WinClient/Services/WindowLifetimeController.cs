using System;

namespace Skybridge.WinClient.Services;

/// <summary>Owns close intent; hiding must never invoke the shutdown/disposal path.</summary>
internal sealed class WindowLifetimeController(Func<bool> ensureTray, Action hideWindow)
{
    public bool ExitRequested { get; private set; }
    public bool SessionEnding { get; set; }

    public void RequestExit() => ExitRequested = true;
    public void CancelExit() => ExitRequested = false;

    public bool HandleClose(bool closeToTray)
    {
        if (!closeToTray || ExitRequested || SessionEnding) return false;
        if (!ensureTray()) throw new InvalidOperationException("The notification area icon is unavailable.");
        hideWindow();
        return true;
    }
}
