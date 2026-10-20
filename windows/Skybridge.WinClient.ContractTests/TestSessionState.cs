using Skybridge.WinClient.Services;

// Account-client fixtures only. Filesystem/DPAPI and cross-process ownership are
// tested separately using the real SessionStore, never this in-memory double.
internal class TestSessionState : ISessionStore, ISessionVerificationStore
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
        LoadResult = SessionStoreLoadResult.Loaded(value, NextVersion(), login) with {
            AudioState = mode == SessionStoreSaveMode.ContinueLogin ? LoadResult.AudioState : null,
            PendingVerificationId = mode == SessionStoreSaveMode.ContinueLogin ? LoadResult.PendingVerificationId : null
        };
        return SessionStoreWriteResult.Saved(LoadResult.Version!, login);
    }
    public SessionStoreWriteResult BeginVerification(SessionStoreVersion expected, Guid loginId, Guid observationId, bool retireAudio) =>
        Verify(expected, loginId, observationId, retireAudio, complete: false);
    public SessionStoreWriteResult CompleteVerification(SessionStoreVersion expected, Guid loginId, Guid observationId, bool retireAudio) =>
        Verify(expected, loginId, observationId, retireAudio, complete: true);
    private SessionStoreWriteResult Verify(SessionStoreVersion expected, Guid loginId, Guid id, bool retireAudio, bool complete)
    {
        if (expected != LoadResult.Version || loginId != LoadResult.LoginId || complete && LoadResult.PendingVerificationId != id)
            return SessionStoreWriteResult.Conflict();
        if (!LoadResult.Succeeded || !complete && LoadResult.PendingVerificationId is not null && !retireAudio)
            return SessionStoreWriteResult.InvalidRecord();
        var version = NextVersion();
        LoadResult = LoadResult with { Version = version, PendingVerificationId = complete ? null : id,
            AudioState = retireAudio ? null : LoadResult.AudioState };
        return SessionStoreWriteResult.Saved(version, loginId);
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
