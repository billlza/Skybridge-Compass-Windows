using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Skybridge.WinClient.Services;

/// <summary>UI-thread-owned Win32 notification icon for the unpackaged WinUI window.</summary>
internal sealed class WindowsTrayIcon : IDisposable
{
    private const uint CallbackMessage = 0x8000 + 71;
    private const uint IconId = 1;
    private const nuint SubclassId = 0x53425452;
    private readonly nint _window;
    private readonly nint _icon;
    private readonly SubclassProc _callback;
    private readonly uint _taskbarCreated;
    private readonly Action _open;
    private readonly Action _exit;
    private readonly Action<Exception> _failure;
    private readonly Action<bool> _sessionEnding;
    private readonly string _title;
    private readonly string _openText;
    private readonly string _exitText;
    private bool _registered;
    private bool _disposed;

    public WindowsTrayIcon(nint window, string iconPath, string title, string openText, string exitText,
        Action open, Action exit, Action<Exception> failure, Action<bool> sessionEnding)
    {
        _window = window;
        _title = title.Length <= 127 ? title : title[..127];
        _openText = openText;
        _exitText = exitText;
        _open = open;
        _exit = exit;
        _failure = failure;
        _sessionEnding = sessionEnding;
        _callback = WindowProc;
        _taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
        if (_taskbarCreated == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        _icon = LoadImageW(0, iconPath, 1, GetSystemMetrics(49), GetSystemMetrics(50), 0x10);
        if (_icon == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (!SetWindowSubclass(_window, _callback, SubclassId, 0))
        {
            DestroyIcon(_icon);
            throw new InvalidOperationException("Unable to attach the notification icon to the window.");
        }
    }

    public bool EnsureVisible()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var data = CreateData();
        // Verify a registered icon still exists before allowing the only window to hide.
        if (_registered && Shell_NotifyIconW(1, ref data)) return true;
        _registered = Shell_NotifyIconW(0, ref data);
        if (!_registered) return false;
        data.Version = 4;
        if (Shell_NotifyIconW(4, ref data)) return true;
        Remove();
        return false;
    }

    public void Remove()
    {
        if (!_registered) return;
        var data = CreateData();
        if (!Shell_NotifyIconW(2, ref data))
            WindowsRuntimeLog.Write(WindowsLogLevel.Warning, "tray", "Notification icon removal failed or Explorer already removed it.");
        _registered = false;
    }

    private NotifyIconData CreateData() => new()
    {
        Size = (uint)Marshal.SizeOf<NotifyIconData>(), Window = _window, Id = IconId,
        Flags = 1 | 2 | 4 | 0x80, Callback = CallbackMessage, Icon = _icon, Tip = _title,
        Info = string.Empty, InfoTitle = string.Empty
    };

    private nint WindowProc(nint window, uint message, nuint wParam, nint lParam, nuint id, nuint data)
    {
        // No managed exception may escape the native callback. Surface a failure and restore
        // access to the window; the caller records the original exception.
        try
        {
            if (message == _taskbarCreated && _registered)
            {
                _registered = false;
                if (!EnsureVisible()) throw new InvalidOperationException("Explorer restarted but the notification icon could not be restored.");
            }
            else if (message == 0x0011) _sessionEnding(true); // WM_QUERYENDSESSION
            else if (message == 0x0016) _sessionEnding(wParam != 0); // WM_ENDSESSION (including cancellation)
            else if (message == CallbackMessage)
            {
                var notification = (uint)((long)lParam & 0xffff);
                if (notification is 0x0400 or 0x0401) _open(); // NIN_SELECT / NIN_KEYSELECT
                else if (notification == 0x007b) ShowMenu(wParam); // WM_CONTEXTMENU, version 4
                return 0;
            }
        }
        catch (Exception error) { _failure(error); }
        return DefSubclassProc(window, message, wParam, lParam);
    }

    private void ShowMenu(nuint position)
    {
        var menu = CreatePopupMenu();
        if (menu == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            if (!AppendMenuW(menu, 0, 1, _openText) || !AppendMenuW(menu, 0x800, 0, null) ||
                !AppendMenuW(menu, 0, 2, _exitText) || !SetMenuDefaultItem(menu, 1, false))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var x = unchecked((short)(position & 0xffff));
            var y = unchecked((short)((position >> 16) & 0xffff));
            // Version 4 supplies the icon anchor for keyboard invocation as well as the mouse.
            SetForegroundWindow(_window);
            var command = TrackPopupMenu(menu, 0x100 | 0x2, x, y, 0, _window, 0);
            PostMessageW(_window, 0, 0, 0); // Required so clicking elsewhere dismisses subsequent menus.
            if (command == 1) _open();
            else if (command == 2) _exit();
        }
        finally { DestroyMenu(menu); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Remove();
        if (!RemoveWindowSubclass(_window, _callback, SubclassId))
            WindowsRuntimeLog.Write(WindowsLogLevel.Warning, "tray", "Unable to detach the closing window's notification callback.");
        DestroyIcon(_icon);
        _disposed = true;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size;
        public nint Window;
        public uint Id, Flags, Callback;
        public nint Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint Version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string InfoTitle;
        public uint InfoFlags;
        public Guid Guid;
        public nint BalloonIcon;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint SubclassProc(nint window, uint message, nuint wParam, nint lParam, nuint id, nuint data);
    [DllImport("comctl32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(nint window, SubclassProc callback, nuint id, nuint data);
    [DllImport("comctl32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(nint window, SubclassProc callback, nuint id);
    [DllImport("comctl32.dll")]
    private static extern nint DefSubclassProc(nint window, uint message, nuint wParam, nint lParam);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Shell_NotifyIconW(uint message, ref NotifyIconData data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessageW(string name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint LoadImageW(nint instance, string name, uint type, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyIcon(nint icon);
    [DllImport("user32.dll", SetLastError = true)] private static extern nint CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AppendMenuW(nint menu, uint flags, nuint id, string? text);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetMenuDefaultItem(nint menu, uint item, [MarshalAs(UnmanagedType.Bool)] bool byPosition);
    [DllImport("user32.dll")] private static extern uint TrackPopupMenu(nint menu, uint flags, int x, int y, int reserved, nint window, nint rect);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyMenu(nint menu);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetForegroundWindow(nint window);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PostMessageW(nint window, uint message, nuint wParam, nint lParam);
}
