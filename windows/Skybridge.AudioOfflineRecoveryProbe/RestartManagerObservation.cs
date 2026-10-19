using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace Skybridge.AudioOfflineRecoveryProbe;

// Registers only this experiment's synthetic lease file, queries its users and
// closes the observation session. Never invokes shutdown/restart or changes an ACL.
internal static class RestartManagerObservation
{
    internal sealed record Owner(uint ProcessId, ulong StartedFileTime, string? Application, string? Service,
        int ApplicationType, uint ApplicationStatus, uint SessionId);
    internal sealed record Observation(string Stage, int Error, uint Needed, uint RebootReasons, Owner[] Owners,
        int? EndSessionError = null, string? ExceptionType = null);

    internal static Observation Read(string path)
    {
        if (Marshal.SizeOf<NativeProcess>() != 12 || Marshal.SizeOf<NativeInfo>() != 668)
            throw new InvalidOperationException("Restart Manager ABI layout is unexpected.");
        int error = RmStartSession(out uint session, 0, new StringBuilder(33));
        if (error != 0) return new("start", error, 0, 0, []);
        Observation result;
        int end;
        try
        {
            error = RmRegisterResources(session, 1, [Path.GetFullPath(path)], 0, IntPtr.Zero, 0, IntPtr.Zero);
            result = error == 0 ? ReadList(session) : new("register", error, 0, 0, []);
        }
        catch (Exception failure)
        { result = new("observer-exception", failure.HResult, 0, 0, [], ExceptionType: failure.GetType().FullName); }
        finally { end = RmEndSession(session); }
        return result with { EndSessionError = end == 0 ? null : end };
    }

    private static Observation ReadList(uint session)
    {
        uint count = 0;
        int error = RmGetList(session, out uint needed, ref count, null, out uint reasons);
        for (int attempt = 0; attempt < 3 && error == 234; attempt++)
        {
            if (needed is 0 or > 128) return new("capacity", error, needed, reasons, []);
            var rows = new NativeInfo[needed]; count = needed;
            error = RmGetList(session, out needed, ref count, rows, out reasons);
            if (error == 0)
            {
                if (count > rows.Length) throw new InvalidDataException("Restart Manager returned more owners than the provided buffer.");
                return new("list", 0, needed, reasons, rows.Take(checked((int)count)).Select(row => new Owner(
                    row.Process.Id, ((ulong)(uint)row.Process.Started.dwHighDateTime << 32) | (uint)row.Process.Started.dwLowDateTime,
                    row.Application, row.Service, row.ApplicationType, row.Status, row.Session)).ToArray());
            }
        }
        return new("list", error, needed, reasons, []);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeProcess { public uint Id; public FILETIME Started; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeInfo
    {
        public NativeProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string? Application;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string? Service;
        public int ApplicationType;
        public uint Status;
        public uint Session;
        public int Restartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint handle, uint flags, StringBuilder key);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint handle, uint fileCount, string[] fileNames,
        uint appCount, IntPtr applications, uint serviceCount, IntPtr serviceNames);
    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] NativeInfo[]? rows, out uint reasons);
    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint handle);
}
