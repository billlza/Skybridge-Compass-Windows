using System.Diagnostics;

// Test infrastructure only. WaitForExitAsync can take the HasExited/exit-code
// fast path before Windows signals the process object. Storage assertions need
// the actual termination boundary, including closure of the child's handles.
internal static class ProcessTerminationBarrier
{
    internal static void Require(Process process, TimeSpan timeout)
    {
        // The timed synchronous overload waits on the process handle on Windows.
        // This is an event wait, not a delay or a retry of the operation under test.
        if (!process.WaitForExit(timeout))
            throw new TimeoutException("The child process did not complete termination within the test deadline.");
    }
}
