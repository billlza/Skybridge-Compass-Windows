using Skybridge.WinClient.Services;

// Account-client fixtures only. Filesystem/DPAPI and cross-process ownership are
// tested separately using the real SessionStore, never this in-memory double.
internal class TestSessionState : ISessionStore
{
    public SessionStoreLoadResult LoadResult { get; set; } = SessionStoreLoadResult.Missing();
    public SessionStoreWriteResult? SaveResult { get; set; }
    public SessionStoreWriteResult? ClearResult { get; set; }
    public int SaveCalls { get; private set; }
    public int ClearCalls { get; private set; }
    public bool ClearCalled => ClearCalls != 0;
    public PersistedSession? LastSaved { get; private set; }
    internal int FailSaveAt;
    internal bool FailClear;
    internal Action? BeforeSave;
    internal PersistedSession? Value
    {
        get => LoadResult.Session;
        set => LoadResult = value is null ? SessionStoreLoadResult.Cleared(NextVersion()) : Loaded(value);
    }
    internal static SessionStoreLoadResult Loaded(PersistedSession value) =>
        SessionStoreLoadResult.Loaded(value, NextVersion());
    private static SessionStoreVersion NextVersion() => SessionStoreVersion.FromBytes(Guid.NewGuid().ToByteArray());
    public SessionStoreLoadResult Load() => LoadResult;
    public SessionStoreWriteResult Save(PersistedSession value, SessionStoreVersion expected, SessionStoreSaveMode mode)
    {
        BeforeSave?.Invoke(); SaveCalls++; LastSaved = value;
        if (SaveResult is { } failure) return failure;
        if (SaveCalls == FailSaveAt) return SessionStoreWriteResult.IoFailure();
        if (expected != LoadResult.Version) return SessionStoreWriteResult.Conflict();
        var login = mode == SessionStoreSaveMode.NewLogin ? Guid.NewGuid() : LoadResult.LoginId ?? Guid.NewGuid();
        LoadResult = SessionStoreLoadResult.Loaded(value, NextVersion(), login);
        return SessionStoreWriteResult.Saved(LoadResult.Version!, login);
    }
    public SessionStoreWriteResult Clear(SessionStoreVersion expected)
    {
        ClearCalls++;
        if (ClearResult is { } failure) return failure;
        if (FailClear) return SessionStoreWriteResult.IoFailure();
        if (expected != LoadResult.Version) return SessionStoreWriteResult.Conflict();
        var version = NextVersion(); LoadResult = SessionStoreLoadResult.Cleared(version);
        return SessionStoreWriteResult.Cleared(version);
    }
}
