using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Skybridge.WinClient.Services.Audio;

/// <summary>The existing Windows output wait and MMCSS lifetime, shared with
/// native qualification. Every operation belongs to its creating render thread.
/// It changes neither system timer resolution nor the source/output format.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsAudioRenderPacing : IDisposable
{
    private readonly int _threadId = Environment.CurrentManagedThreadId;
    private readonly ProgressTimer _timer;
    private readonly WaitHandle[] _waitHandles;
    private IntPtr _mmcss;
    private bool _disposed;
    private AggregateException? _cleanupFailure;

    internal WindowsAudioRenderPacing()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows audio pacing requires Windows.");
        _timer = new ProgressTimer();
        _waitHandles = [_timer, _timer];
    }

    internal void Start()
    {
        Check();
        if (_mmcss != IntPtr.Zero) throw new InvalidOperationException("Audio pacing is already registered with MMCSS.");
        uint taskIndex = 0;
        _mmcss = AvSetMmThreadCharacteristics("Audio", ref taskIndex);
        if (_mmcss == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to register the output thread with MMCSS.");
    }

    internal void Wait(TimeSpan delay, CancellationToken cancellationToken)
    {
        Check();
        if (delay <= TimeSpan.Zero || delay > TimeSpan.FromMilliseconds(5)) throw new ArgumentOutOfRangeException(nameof(delay));
        cancellationToken.ThrowIfCancellationRequested();
        _waitHandles[0] = cancellationToken.WaitHandle;
        _timer.Schedule(delay);
        var result = WaitHandle.WaitAny(_waitHandles, delay + TimeSpan.FromMilliseconds(250));
        if (result == 0) throw new OperationCanceledException(cancellationToken);
        if (result == WaitHandle.WaitTimeout) throw new TimeoutException("The output pacing timer did not signal.");
        cancellationToken.ThrowIfCancellationRequested();
    }

    public void Dispose()
    {
        RequireThread();
        if (_disposed)
        {
            if (_cleanupFailure is not null) throw _cleanupFailure;
            return;
        }
        _disposed = true;
        var errors = new List<Exception>();
        if (_mmcss != IntPtr.Zero)
        {
            if (!AvRevertMmThreadCharacteristics(_mmcss))
                errors.Add(new Win32Exception(Marshal.GetLastWin32Error(), "Unable to revert output MMCSS registration."));
            else _mmcss = IntPtr.Zero;
        }
        try { _timer.Dispose(); }
        catch (Exception failure) { errors.Add(failure); }
        if (errors.Count != 0)
        {
            _cleanupFailure = new AggregateException("Windows audio pacing release is unconfirmed.", errors);
            throw _cleanupFailure;
        }
    }

    private void RequireThread()
    {
        if (Environment.CurrentManagedThreadId != _threadId)
            throw new InvalidOperationException("Native audio pacing must remain on its owning thread.");
    }
    private void Check() { RequireThread(); ObjectDisposedException.ThrowIf(_disposed, this); }

    private sealed class ProgressTimer : WaitHandle
    {
        internal ProgressTimer()
        {
            // HIGH_RESOLUTION; SYNCHRONIZE | TIMER_MODIFY_STATE. No global timer-resolution change.
            var handle = CreateWaitableTimerEx(IntPtr.Zero, null, 0x00000002, 0x00100002);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error(); handle.Dispose();
                throw new Win32Exception(error, "Unable to create the output pacing timer.");
            }
            SafeWaitHandle = handle;
        }
        internal void Schedule(TimeSpan delay)
        {
            long due = -delay.Ticks;
            if (!SetWaitableTimer(SafeWaitHandle, ref due, 0, IntPtr.Zero, IntPtr.Zero, false))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to schedule output pacing.");
        }
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateWaitableTimerExW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle CreateWaitableTimerEx(IntPtr attributes, string? name, uint flags, uint access);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWaitableTimer(SafeWaitHandle timer, ref long due, int period, IntPtr completion, IntPtr context,
        [MarshalAs(UnmanagedType.Bool)] bool resume);
    [DllImport("avrt.dll", EntryPoint = "AvSetMmThreadCharacteristicsW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr AvSetMmThreadCharacteristics(string taskName, ref uint taskIndex);
    [DllImport("avrt.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AvRevertMmThreadCharacteristics(IntPtr handle);
}
