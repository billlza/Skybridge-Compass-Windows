using Skybridge.WinClient.Services;

internal static class SessionFileCommitTests
{
    internal static IEnumerable<(string Name, Func<Task> Run)> Cases =>
    [
        ("session commit publishes a new file and replaces the complete prior file", () => Run(Publish)),
        ("session commit rejects a different directory before changing either file", () => Run(RejectDifferentDirectory)),
        ("session commit rejects the destination as its own temporary file", () => Run(RejectSelf)),
        ("session commit missing temporary file preserves the prior record", () => Run(MissingTemporary)),
        ("session commit directory destination preserves the prepared record", () => Run(DirectoryDestination)),
        ("session commit handles long Unicode paths", () => Run(LongPath))
    ];

    private static Task Run(Action<string> test)
    {
        var directory = Directory.CreateTempSubdirectory("skybridge-session-commit-").FullName;
        try { test(directory); }
        finally { Directory.Delete(directory, recursive: true); }
        return Task.CompletedTask;
    }

    private static void Publish(string directory)
    {
        var temporary = Path.Combine(directory, ".prepared.tmp");
        var destination = Path.Combine(directory, "record.bin");
        foreach (var value in new[] { new byte[] { 1, 2, 3 }, Enumerable.Repeat((byte)7, 65_536).ToArray() })
        {
            WritePrepared(temporary, value);
            AtomicSessionFileCommitter.Instance.Commit(temporary, destination);
            Require(File.ReadAllBytes(destination).SequenceEqual(value), "Committed content was incomplete.");
            Require(!File.Exists(temporary), "The committed temporary file still exists.");
        }
    }

    private static void RejectDifferentDirectory(string directory)
    {
        var other = Directory.CreateDirectory(Path.Combine(directory, "other")).FullName;
        var temporary = Path.Combine(other, "prepared.tmp");
        var destination = Path.Combine(directory, "record.bin");
        WritePrepared(temporary, [2]); WritePrepared(destination, [1]);
        Reject<ArgumentException>(() => AtomicSessionFileCommitter.Instance.Commit(temporary, destination));
        Require(File.ReadAllBytes(temporary).SequenceEqual(new byte[] { 2 }) &&
            File.ReadAllBytes(destination).SequenceEqual(new byte[] { 1 }), "Rejected commit changed a file.");
    }

    private static void RejectSelf(string directory)
    {
        var destination = Path.Combine(directory, "record.bin"); WritePrepared(destination, [1]);
        Reject<ArgumentException>(() => AtomicSessionFileCommitter.Instance.Commit(destination, destination));
        Require(File.ReadAllBytes(destination).SequenceEqual(new byte[] { 1 }), "Self commit changed the record.");
    }

    private static void MissingTemporary(string directory)
    {
        var destination = Path.Combine(directory, "record.bin"); WritePrepared(destination, [1]);
        Reject<IOException>(() => AtomicSessionFileCommitter.Instance.Commit(Path.Combine(directory, "missing.tmp"), destination));
        Require(File.ReadAllBytes(destination).SequenceEqual(new byte[] { 1 }), "Missing source changed the record.");
    }

    private static void DirectoryDestination(string directory)
    {
        var destination = Directory.CreateDirectory(Path.Combine(directory, "record.bin")).FullName;
        var temporary = Path.Combine(directory, "prepared.tmp"); WritePrepared(temporary, [2]);
        Reject<IOException>(() => AtomicSessionFileCommitter.Instance.Commit(temporary, destination));
        Require(Directory.Exists(destination) && File.ReadAllBytes(temporary).SequenceEqual(new byte[] { 2 }),
            "Failed directory replacement changed the prepared record.");
    }

    private static void LongPath(string directory)
    {
        for (int i = 0; i < 4; i++) directory = Path.Combine(directory, "音频-" + new string('p', 80));
        Directory.CreateDirectory(directory);
        Publish(directory);
    }

    internal static void WritePrepared(string path, byte[] bytes)
    {
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        output.Write(bytes); output.Flush(flushToDisk: true);
    }

    private static void Reject<T>(Action operation) where T : Exception
    {
        try { operation(); }
        catch (T) { return; }
        throw new InvalidOperationException("Expected " + typeof(T).Name + ".");
    }
    private static void Require(bool condition, string message)
    { if (!condition) throw new InvalidOperationException(message); }
}
