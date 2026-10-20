using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services;

public interface ISessionStore
{
    SessionStoreLoadResult Load();
    SessionStoreWriteResult Save(PersistedSession session, SessionStoreVersion expected, SessionStoreSaveMode mode);
    SessionStoreWriteResult Clear(SessionStoreVersion expected);
}

// The storage layer owns atomicity and account ownership, not interpretation of
// audio authority. The audio layer must validate the bounded JSON state before
// admitting it. This capability writes the SAME protected account record.
internal interface ISessionAudioStateStore
{
    SessionStoreWriteResult WriteAudioState(JsonElement state, SessionStoreVersion expected, Guid expectedLogin);
}

public enum SessionStoreSaveMode { NewLogin, ContinueLogin }

// An opaque revision of the exact protected bytes, including a fresh mutation nonce.
// Missing is also a captured state; a completed clear replaces it with a tombstone.
public sealed record SessionStoreVersion
{
    private readonly string _digest;
    private SessionStoreVersion(string digest) => _digest = digest;
    public static SessionStoreVersion Missing { get; } = new("");
    internal static SessionStoreVersion FromBytes(byte[] bytes) => new(Convert.ToHexString(SHA256.HashData(bytes)));
}

public sealed class DpapiSessionProtector : ISessionProtector
{
    public byte[] Protect(byte[] bytes)
    {
        if (!IsWindowsDpapiSupported())
        {
            throw new PlatformNotSupportedException("SkyBridge Windows session protection requires Windows DPAPI.");
        }

        return ProtectedData.Protect(bytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
    }

    public byte[] Unprotect(byte[] bytes)
    {
        if (!IsWindowsDpapiSupported())
        {
            throw new PlatformNotSupportedException("SkyBridge Windows session protection requires Windows DPAPI.");
        }

        return ProtectedData.Unprotect(bytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
    }

    [SupportedOSPlatformGuard("windows")]
    private static bool IsWindowsDpapiSupported() => OperatingSystem.IsWindows();
}

// One account record and one permanent lease file. All current product writers
// compare their captured revision under the same lease before replacing session.bin.
// Schema-1 credentials migrate on a verified save; they carry no offline authority.
public sealed class SessionStore : ISessionStore, ISessionAudioStateStore
{
    private const int MaximumRecordBytes = 1_048_576;
    private const int EnvelopeSchema = 3;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly string _directory;
    private readonly string _filePath;
    private readonly ISessionProtector _protector;
    private readonly ISessionFileCommitter _fileCommitter;

    public SessionStore(string? directory = null, ISessionProtector? protector = null)
        : this(directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SkyBridge"),
            protector ?? new DpapiSessionProtector(), AtomicSessionFileCommitter.Instance) { }

    internal SessionStore(string directory, ISessionProtector protector, ISessionFileCommitter fileCommitter)
    {
        _directory = string.IsNullOrWhiteSpace(directory)
            ? throw new ArgumentException("Session directory is required.", nameof(directory)) : Path.GetFullPath(directory);
        _filePath = Path.Combine(_directory, "session.bin");
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _fileCommitter = fileCommitter ?? throw new ArgumentNullException(nameof(fileCommitter));
    }

    public SessionStoreLoadResult Load()
    {
        string operation = "InspectDirectory";
        try
        {
            // GetAttributes may report a missing final directory as file-not-
            // found. Only absence at this boundary is a fresh account store;
            // a permission failure, a non-directory, or a later lease/read
            // race must keep its I/O failure instead of becoming signed out.
            try { RequireDirectory(); }
            catch (FileNotFoundException) { return SessionStoreLoadResult.Missing(); }
            catch (DirectoryNotFoundException) { return SessionStoreLoadResult.Missing(); }
            operation = "AcquireLease";
            using var lease = AcquireLease();
            operation = "ReadRecord";
            return ReadHead();
        }
        catch (IOException error) { return SessionStoreLoadResult.IoFailure(SessionStoreFailure.From(operation, error)); }
        catch (UnauthorizedAccessException error) { return SessionStoreLoadResult.IoFailure(SessionStoreFailure.From(operation, error)); }
    }

    public SessionStoreWriteResult Save(PersistedSession session, SessionStoreVersion expected, SessionStoreSaveMode mode)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (mode is not (SessionStoreSaveMode.NewLogin or SessionStoreSaveMode.ContinueLogin))
            throw new ArgumentOutOfRangeException(nameof(mode));
        var validation = Validate(session);
        if (validation != PersistedSessionValidation.Valid) return WriteValidationFailure(validation);
        string operation = "PrepareDirectory";
        try
        {
            Directory.CreateDirectory(_directory);
            operation = "AcquireLease";
            using var lease = AcquireLease();
            operation = "ReadRecord";
            var current = ReadHead();
            if (current.Version is null) return SessionStoreWriteResult.InvalidRecord();
            if (current.Version != expected) return SessionStoreWriteResult.Conflict();
            if (!current.Succeeded && !current.IsQuietSignedOut) return SessionStoreWriteResult.InvalidRecord(current.Failure);
            if (mode == SessionStoreSaveMode.ContinueLogin)
            {
                if (current.Session is not { } prior) return SessionStoreWriteResult.InvalidSession();
                if (prior.Authority != session.Authority) return SessionStoreWriteResult.AuthorityMismatch();
                if (prior.Subject != session.Subject) return SessionStoreWriteResult.SubjectMismatch();
            }
            var login = mode == SessionStoreSaveMode.NewLogin ? Guid.NewGuid() : current.LoginId ?? Guid.NewGuid();
            return Commit(new(EnvelopeSchema, Guid.NewGuid(), "active", login, session,
                mode == SessionStoreSaveMode.ContinueLogin ? current.AudioState : null));
        }
        catch (IOException error) { return SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
        catch (UnauthorizedAccessException error) { return SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
    }

    SessionStoreWriteResult ISessionAudioStateStore.WriteAudioState(JsonElement state, SessionStoreVersion expected, Guid expectedLogin)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (expectedLogin == Guid.Empty) throw new ArgumentException("A durable account owner is required.", nameof(expectedLogin));
        if (state.ValueKind != JsonValueKind.Object) return SessionStoreWriteResult.InvalidRecord();
        try { RequireUniqueFields(state); }
        catch (JsonException) { return SessionStoreWriteResult.InvalidRecord(); }
        string operation = "AcquireLease";
        try
        {
            using var lease = AcquireLease();
            operation = "ReadRecord";
            var current = ReadHead();
            if (current.Version is null) return SessionStoreWriteResult.InvalidRecord(current.Failure);
            if (current.Version != expected || current.LoginId != expectedLogin) return SessionStoreWriteResult.Conflict();
            if (!current.Succeeded || current.Session is null) return SessionStoreWriteResult.InvalidRecord(current.Failure);
            // Credentials and login identity are retained from the protected head,
            // never supplied by an audio callback. The mutation gets a new revision.
            return Commit(new(EnvelopeSchema, Guid.NewGuid(), "active", expectedLogin, current.Session, state));
        }
        catch (IOException error) { return SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
        catch (UnauthorizedAccessException error) { return SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
    }

    public SessionStoreWriteResult Clear(SessionStoreVersion expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        string operation = "PrepareDirectory";
        try
        {
            Directory.CreateDirectory(_directory);
            operation = "AcquireLease";
            using var lease = AcquireLease();
            operation = "ReadRecord";
            var current = ReadHead();
            if (current.Version is null) return SessionStoreWriteResult.InvalidRecord();
            if (current.Version != expected) return SessionStoreWriteResult.Conflict();
            if (current.Status == SessionStoreLoadStatus.Cleared) return SessionStoreWriteResult.Cleared(expected);
            // Explicit clearing may retire corrupt data only if the caller captured
            // those exact bytes. Startup does not automatically invoke this path.
            return Commit(new(EnvelopeSchema, Guid.NewGuid(), "cleared", null, null));
        }
        catch (IOException error) { return SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
        catch (UnauthorizedAccessException error) { return SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
    }

    private FileStream AcquireLease()
    {
        RequireDirectory();
        var path = Path.Combine(_directory, ".session.lock");
        RejectLinkIfPresent(path);
        // Fail promptly on contention; never remove the lease file or wait on a
        // network request while holding it. OS handle release also covers crashes.
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private void RequireDirectory()
    {
        var attributes = File.GetAttributes(_directory);
        if ((attributes & FileAttributes.ReparsePoint) != 0 || (attributes & FileAttributes.Directory) == 0)
            throw new IOException("Protected account state requires a directory without a filesystem link.");
    }

    private SessionStoreLoadResult ReadHead()
    {
        RejectLinkIfPresent(_filePath);
        byte[] protectedBytes;
        try
        {
            using var input = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length > MaximumRecordBytes) return SessionStoreLoadResult.InvalidSession();
            protectedBytes = new byte[checked((int)input.Length)];
            input.ReadExactly(protectedBytes);
            if (input.ReadByte() != -1) throw new IOException("Session record changed during its read.");
        }
        catch (FileNotFoundException) { return SessionStoreLoadResult.Missing(); }
        var version = SessionStoreVersion.FromBytes(protectedBytes);
        byte[]? json = null;
        try
        {
            if (protectedBytes.Length == 0) return SessionStoreLoadResult.EmptyFile(version);
            json = _protector.Unprotect(protectedBytes);
            if (json.Length is <= 0 or > MaximumRecordBytes) return SessionStoreLoadResult.InvalidSession(version);
            using var document = JsonDocument.Parse(json);
            RequireUniqueFields(document.RootElement);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("schemaVersion", out var schema) || schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out int number))
                return SessionStoreLoadResult.SchemaMismatch(version);
            PersistedSession? session;
            Guid? login;
            JsonElement? audioState = null;
            if (number == PersistedSession.CurrentSchemaVersion)
            {
                session = JsonSerializer.Deserialize<PersistedSession>(json, JsonOptions);
                login = null; // Legacy credentials do not establish a durable login or grant.
            }
            else if (number is 2 or EnvelopeSchema)
            {
                var envelope = JsonSerializer.Deserialize<Envelope>(json, JsonOptions);
                if (envelope is null || envelope.Revision == Guid.Empty) return SessionStoreLoadResult.InvalidSession(version);
                if (envelope.State == "cleared" && envelope.LoginId is null && envelope.Session is null && envelope.AudioState is null)
                    return SessionStoreLoadResult.Cleared(version);
                if (envelope.State != "active" || envelope.LoginId is null || envelope.LoginId == Guid.Empty || envelope.Session is null)
                    return SessionStoreLoadResult.InvalidSession(version);
                session = envelope.Session; login = envelope.LoginId;
                if (envelope.AudioState is { } audio)
                {
                    if (number != EnvelopeSchema || audio.ValueKind != JsonValueKind.Object)
                        return SessionStoreLoadResult.InvalidSession(version);
                    audioState = audio.Clone();
                }
            }
            else return SessionStoreLoadResult.SchemaMismatch(version);
            return Validate(session) switch
            {
                PersistedSessionValidation.Valid => SessionStoreLoadResult.Loaded(session!, version, login) with { AudioState = audioState },
                PersistedSessionValidation.SchemaMismatch => SessionStoreLoadResult.SchemaMismatch(version),
                PersistedSessionValidation.AuthorityMismatch => SessionStoreLoadResult.AuthorityMismatch(version),
                PersistedSessionValidation.SubjectMismatch => SessionStoreLoadResult.SubjectMismatch(version),
                _ => SessionStoreLoadResult.InvalidSession(version)
            };
        }
        catch (CryptographicException error) { return SessionStoreLoadResult.DecryptFailed(version, SessionStoreFailure.From("UnprotectRecord", error)); }
        catch (PlatformNotSupportedException error) { return SessionStoreLoadResult.DecryptFailed(version, SessionStoreFailure.From("UnprotectRecord", error)); }
        catch (JsonException) { return SessionStoreLoadResult.InvalidJson(version); }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (json is not null) CryptographicOperations.ZeroMemory(json);
        }
    }

    private SessionStoreWriteResult Commit(Envelope envelope)
    {
        byte[]? json = null, protectedBytes = null;
        string? temporary = null;
        SessionStoreWriteResult? result = null;
        string operation = "ProtectRecord";
        try
        {
            json = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
            if (json.Length > MaximumRecordBytes) return SessionStoreWriteResult.InvalidSession();
            protectedBytes = _protector.Protect(json);
            if (protectedBytes.Length is <= 0 or > MaximumRecordBytes) return SessionStoreWriteResult.CryptoFailure();
            var version = SessionStoreVersion.FromBytes(protectedBytes);
            temporary = Path.Combine(_directory, $".session.bin.{Guid.NewGuid():N}.tmp");
            operation = "WriteTemporaryRecord";
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { output.Write(protectedBytes); output.Flush(flushToDisk: true); }
            operation = "ReplaceRecord";
            _fileCommitter.Commit(temporary, _filePath);
            temporary = null;
            result = envelope.LoginId is { } login ? SessionStoreWriteResult.Saved(version, login) : SessionStoreWriteResult.Cleared(version);
        }
        catch (CryptographicException error) { result = SessionStoreWriteResult.CryptoFailure(SessionStoreFailure.From(operation, error)); }
        catch (PlatformNotSupportedException error) { result = SessionStoreWriteResult.CryptoFailure(SessionStoreFailure.From(operation, error)); }
        catch (IOException error) { result = SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
        catch (UnauthorizedAccessException error) { result = SessionStoreWriteResult.IoFailure(SessionStoreFailure.From(operation, error)); }
        finally
        {
            if (json is not null) CryptographicOperations.ZeroMemory(json);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            if (temporary is not null)
            {
                try { File.Delete(temporary); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    result = (result ?? SessionStoreWriteResult.IoFailure()) with
                    { Status = SessionStoreWriteStatus.IoFailure, CleanupFailure = SessionStoreFailure.From("CleanupTemporaryRecord", error) };
                }
            }
        }
        return result ?? throw new InvalidOperationException("Session commit completed without a typed result.");
    }

    private static void RejectLinkIfPresent(string path)
    { try { RejectLink(path); } catch (FileNotFoundException) { return; } }
    private static void RejectLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Protected account state cannot use a filesystem link.");
    }
    private static void RequireUniqueFields(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in element.EnumerateObject())
            {
                if (!names.Add(field.Name)) throw new JsonException("Duplicate session field.");
                RequireUniqueFields(field.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RequireUniqueFields(item);
    }

    private static PersistedSessionValidation Validate(PersistedSession? session)
    {
        if (session is null)
        {
            return PersistedSessionValidation.InvalidSession;
        }

        if (session.SchemaVersion != PersistedSession.CurrentSchemaVersion)
        {
            return PersistedSessionValidation.SchemaMismatch;
        }

        if (session.Authority is null || !session.Authority.IsWellFormed())
        {
            return PersistedSessionValidation.AuthorityMismatch;
        }

        if (string.IsNullOrWhiteSpace(session.Subject)
            || session.Subject.Length > 2048
            || session.Subject.Any(char.IsControl))
        {
            return PersistedSessionValidation.SubjectMismatch;
        }

        if (string.IsNullOrWhiteSpace(session.RefreshToken) || session.IssuedAtUnix < 0)
        {
            return PersistedSessionValidation.InvalidSession;
        }

        if (!SessionJwtValidator.TryValidate(
                session.AccessToken,
                session.Authority,
                session.Subject,
                requireUnexpired: false,
                out _,
                out var tokenError))
        {
            if (tokenError.StartsWith("auth_authority_", StringComparison.Ordinal))
            {
                return PersistedSessionValidation.AuthorityMismatch;
            }

            return tokenError is "auth_subject_missing" or "auth_subject_mismatch"
                ? PersistedSessionValidation.SubjectMismatch
                : PersistedSessionValidation.InvalidSession;
        }

        return PersistedSessionValidation.Valid;
    }

    private static SessionStoreWriteResult WriteValidationFailure(PersistedSessionValidation validation) =>
        validation switch
        {
            PersistedSessionValidation.SchemaMismatch => SessionStoreWriteResult.SchemaMismatch(),
            PersistedSessionValidation.AuthorityMismatch => SessionStoreWriteResult.AuthorityMismatch(),
            PersistedSessionValidation.SubjectMismatch => SessionStoreWriteResult.SubjectMismatch(),
            _ => SessionStoreWriteResult.InvalidSession()
        };

    private enum PersistedSessionValidation { Valid, SchemaMismatch, AuthorityMismatch, SubjectMismatch, InvalidSession }
    private sealed record Envelope(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("revision")] Guid Revision,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("loginId")] Guid? LoginId,
        [property: JsonPropertyName("session")] PersistedSession? Session,
        [property: JsonPropertyName("audioState")] JsonElement? AudioState = null);
}

public enum SessionStoreLoadStatus
{
    Loaded, Missing, Cleared, EmptyFile, DecryptFailed, InvalidJson,
    SchemaMismatch, AuthorityMismatch, SubjectMismatch, InvalidSession, IoFailure
}

// Keep native failure context without storing exception messages, paths or credentials.
public sealed record SessionStoreFailure(string Operation, int HResult, int? NativeErrorCode)
{
    internal static SessionStoreFailure From(string operation, Exception error)
    {
        var native = error as System.ComponentModel.Win32Exception ?? error.InnerException as System.ComponentModel.Win32Exception;
        return new(operation, error.HResult, native?.NativeErrorCode);
    }
}

public sealed record SessionStoreLoadResult(SessionStoreLoadStatus Status, PersistedSession? Session,
    SessionStoreVersion? Version = null, Guid? LoginId = null, SessionStoreFailure? Failure = null)
{
    // Opaque, authenticated storage payload. Parsing it is not authorization;
    // the audio layer must verify schema, owner, revocations and finite grants.
    internal JsonElement? AudioState { get; init; }
    public bool Succeeded => Failure is null && Status == SessionStoreLoadStatus.Loaded && Session is not null && Version is not null;
    public bool IsQuietSignedOut => Failure is null && Status is SessionStoreLoadStatus.Missing or SessionStoreLoadStatus.Cleared;
    public static SessionStoreLoadResult Loaded(PersistedSession session, SessionStoreVersion version, Guid? loginId = null) => new(SessionStoreLoadStatus.Loaded, session, version, loginId);
    public static SessionStoreLoadResult Missing() => new(SessionStoreLoadStatus.Missing, null, SessionStoreVersion.Missing);
    public static SessionStoreLoadResult Cleared(SessionStoreVersion version) => new(SessionStoreLoadStatus.Cleared, null, version);
    public static SessionStoreLoadResult EmptyFile(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.EmptyFile, null, version);
    public static SessionStoreLoadResult DecryptFailed(SessionStoreVersion? version = null, SessionStoreFailure? failure = null) => new(SessionStoreLoadStatus.DecryptFailed, null, version, Failure: failure);
    public static SessionStoreLoadResult InvalidJson(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.InvalidJson, null, version);
    public static SessionStoreLoadResult SchemaMismatch(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.SchemaMismatch, null, version);
    public static SessionStoreLoadResult AuthorityMismatch(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.AuthorityMismatch, null, version);
    public static SessionStoreLoadResult SubjectMismatch(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.SubjectMismatch, null, version);
    public static SessionStoreLoadResult InvalidSession(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.InvalidSession, null, version);
    public static SessionStoreLoadResult IoFailure(SessionStoreFailure? failure = null) => new(SessionStoreLoadStatus.IoFailure, null, Failure: failure);
}

public enum SessionStoreWriteStatus
{
    Saved, Cleared, Conflict, InvalidRecord, InvalidSession, SchemaMismatch, AuthorityMismatch,
    SubjectMismatch, CryptoFailure, IoFailure
}

public sealed record SessionStoreWriteResult(SessionStoreWriteStatus Status, SessionStoreVersion? Version = null, Guid? LoginId = null,
    SessionStoreFailure? Failure = null, SessionStoreFailure? CleanupFailure = null)
{
    public bool Succeeded => Failure is null && CleanupFailure is null && Version is not null && (Status == SessionStoreWriteStatus.Cleared ||
        (Status == SessionStoreWriteStatus.Saved && LoginId is { } login && login != Guid.Empty));
    public static SessionStoreWriteResult Saved(SessionStoreVersion version, Guid loginId) => new(SessionStoreWriteStatus.Saved, version, loginId);
    public static SessionStoreWriteResult Cleared(SessionStoreVersion version) => new(SessionStoreWriteStatus.Cleared, version);
    public static SessionStoreWriteResult Conflict() => new(SessionStoreWriteStatus.Conflict);
    public static SessionStoreWriteResult InvalidRecord(SessionStoreFailure? failure = null) => new(SessionStoreWriteStatus.InvalidRecord, Failure: failure);
    public static SessionStoreWriteResult InvalidSession() => new(SessionStoreWriteStatus.InvalidSession);
    public static SessionStoreWriteResult SchemaMismatch() => new(SessionStoreWriteStatus.SchemaMismatch);
    public static SessionStoreWriteResult AuthorityMismatch() => new(SessionStoreWriteStatus.AuthorityMismatch);
    public static SessionStoreWriteResult SubjectMismatch() => new(SessionStoreWriteStatus.SubjectMismatch);
    public static SessionStoreWriteResult CryptoFailure(SessionStoreFailure? failure = null) => new(SessionStoreWriteStatus.CryptoFailure, Failure: failure);
    public static SessionStoreWriteResult IoFailure(SessionStoreFailure? failure = null) => new(SessionStoreWriteStatus.IoFailure, Failure: failure);
}

// The persisted identity + tokens. Kept deliberately small: enough to refresh and then
// re-show the account block only after the live Supabase authority accepts the session.
public sealed record PersistedSession
{
    public const int CurrentSchemaVersion = 1;

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("authority")]
    public SessionAuthority? Authority { get; init; }

    [JsonPropertyName("subject")]
    public string? Subject { get; init; }

    [JsonPropertyName("accessToken")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("refreshToken")]
    public string? RefreshToken { get; init; }

    [JsonPropertyName("nebulaId")]
    public string? NebulaId { get; init; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; init; }

    [JsonPropertyName("avatarUrl")]
    public string? AvatarUrl { get; init; }

    [JsonPropertyName("issuedAtUnix")]
    public long IssuedAtUnix { get; init; }
}
