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
public sealed class SessionStore : ISessionStore
{
    private const int MaximumRecordBytes = 1_048_576;
    private const int EnvelopeSchema = 2;
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
        try { using var lease = AcquireLease(); return ReadHead(); }
        catch (DirectoryNotFoundException) { return SessionStoreLoadResult.Missing(); }
        catch (IOException) { return SessionStoreLoadResult.IoFailure(); }
        catch (UnauthorizedAccessException) { return SessionStoreLoadResult.IoFailure(); }
    }

    public SessionStoreWriteResult Save(PersistedSession session, SessionStoreVersion expected, SessionStoreSaveMode mode)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (mode is not (SessionStoreSaveMode.NewLogin or SessionStoreSaveMode.ContinueLogin))
            throw new ArgumentOutOfRangeException(nameof(mode));
        var validation = Validate(session);
        if (validation != PersistedSessionValidation.Valid) return WriteValidationFailure(validation);
        try
        {
            Directory.CreateDirectory(_directory);
            using var lease = AcquireLease();
            var current = ReadHead();
            if (current.Version is null) return SessionStoreWriteResult.InvalidRecord();
            if (current.Version != expected) return SessionStoreWriteResult.Conflict();
            if (!current.Succeeded && !current.IsQuietSignedOut) return SessionStoreWriteResult.InvalidRecord();
            if (mode == SessionStoreSaveMode.ContinueLogin)
            {
                if (current.Session is not { } prior) return SessionStoreWriteResult.InvalidSession();
                if (prior.Authority != session.Authority) return SessionStoreWriteResult.AuthorityMismatch();
                if (prior.Subject != session.Subject) return SessionStoreWriteResult.SubjectMismatch();
            }
            var login = mode == SessionStoreSaveMode.NewLogin ? Guid.NewGuid() : current.LoginId ?? Guid.NewGuid();
            return Commit(new(EnvelopeSchema, Guid.NewGuid(), "active", login, session));
        }
        catch (IOException) { return SessionStoreWriteResult.IoFailure(); }
        catch (UnauthorizedAccessException) { return SessionStoreWriteResult.IoFailure(); }
    }

    public SessionStoreWriteResult Clear(SessionStoreVersion expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        try
        {
            Directory.CreateDirectory(_directory);
            using var lease = AcquireLease();
            var current = ReadHead();
            if (current.Version is null) return SessionStoreWriteResult.InvalidRecord();
            if (current.Version != expected) return SessionStoreWriteResult.Conflict();
            if (current.Status == SessionStoreLoadStatus.Cleared) return SessionStoreWriteResult.Cleared(expected);
            // Explicit clearing may retire corrupt data only if the caller captured
            // those exact bytes. Startup does not automatically invoke this path.
            return Commit(new(EnvelopeSchema, Guid.NewGuid(), "cleared", null, null));
        }
        catch (IOException) { return SessionStoreWriteResult.IoFailure(); }
        catch (UnauthorizedAccessException) { return SessionStoreWriteResult.IoFailure(); }
    }

    private FileStream AcquireLease()
    {
        RejectLink(_directory);
        var path = Path.Combine(_directory, ".session.lock");
        RejectLinkIfPresent(path);
        // Fail promptly on contention; never remove the lease file or wait on a
        // network request while holding it. OS handle release also covers crashes.
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
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
            if (number == PersistedSession.CurrentSchemaVersion)
            {
                session = JsonSerializer.Deserialize<PersistedSession>(json, JsonOptions);
                login = null; // Legacy credentials do not establish a durable login or grant.
            }
            else if (number == EnvelopeSchema)
            {
                var envelope = JsonSerializer.Deserialize<Envelope>(json, JsonOptions);
                if (envelope is null || envelope.Revision == Guid.Empty) return SessionStoreLoadResult.InvalidSession(version);
                if (envelope.State == "cleared" && envelope.LoginId is null && envelope.Session is null)
                    return SessionStoreLoadResult.Cleared(version);
                if (envelope.State != "active" || envelope.LoginId is null || envelope.LoginId == Guid.Empty || envelope.Session is null)
                    return SessionStoreLoadResult.InvalidSession(version);
                session = envelope.Session; login = envelope.LoginId;
            }
            else return SessionStoreLoadResult.SchemaMismatch(version);
            return Validate(session) switch
            {
                PersistedSessionValidation.Valid => SessionStoreLoadResult.Loaded(session!, version, login),
                PersistedSessionValidation.SchemaMismatch => SessionStoreLoadResult.SchemaMismatch(version),
                PersistedSessionValidation.AuthorityMismatch => SessionStoreLoadResult.AuthorityMismatch(version),
                PersistedSessionValidation.SubjectMismatch => SessionStoreLoadResult.SubjectMismatch(version),
                _ => SessionStoreLoadResult.InvalidSession(version)
            };
        }
        catch (CryptographicException) { return SessionStoreLoadResult.DecryptFailed(version); }
        catch (PlatformNotSupportedException) { return SessionStoreLoadResult.DecryptFailed(version); }
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
        try
        {
            json = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
            if (json.Length > MaximumRecordBytes) return SessionStoreWriteResult.InvalidSession();
            protectedBytes = _protector.Protect(json);
            if (protectedBytes.Length is <= 0 or > MaximumRecordBytes) return SessionStoreWriteResult.CryptoFailure();
            var version = SessionStoreVersion.FromBytes(protectedBytes);
            temporary = Path.Combine(_directory, $".session.bin.{Guid.NewGuid():N}.tmp");
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { output.Write(protectedBytes); output.Flush(flushToDisk: true); }
            _fileCommitter.Commit(temporary, _filePath);
            temporary = null;
            result = envelope.LoginId is { } login ? SessionStoreWriteResult.Saved(version, login) : SessionStoreWriteResult.Cleared(version);
        }
        catch (CryptographicException) { result = SessionStoreWriteResult.CryptoFailure(); }
        catch (PlatformNotSupportedException) { result = SessionStoreWriteResult.CryptoFailure(); }
        catch (IOException) { result = SessionStoreWriteResult.IoFailure(); }
        catch (UnauthorizedAccessException) { result = SessionStoreWriteResult.IoFailure(); }
        finally
        {
            if (json is not null) CryptographicOperations.ZeroMemory(json);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            if (temporary is not null)
            {
                try { File.Delete(temporary); }
                catch (IOException) { result = SessionStoreWriteResult.IoFailure(); }
                catch (UnauthorizedAccessException) { result = SessionStoreWriteResult.IoFailure(); }
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
        [property: JsonPropertyName("session")] PersistedSession? Session);
}

public enum SessionStoreLoadStatus
{
    Loaded, Missing, Cleared, EmptyFile, DecryptFailed, InvalidJson,
    SchemaMismatch, AuthorityMismatch, SubjectMismatch, InvalidSession, IoFailure
}

public sealed record SessionStoreLoadResult(SessionStoreLoadStatus Status, PersistedSession? Session,
    SessionStoreVersion? Version = null, Guid? LoginId = null)
{
    public bool Succeeded => Status == SessionStoreLoadStatus.Loaded && Session is not null && Version is not null;
    public bool IsQuietSignedOut => Status is SessionStoreLoadStatus.Missing or SessionStoreLoadStatus.Cleared;
    public static SessionStoreLoadResult Loaded(PersistedSession session, SessionStoreVersion version, Guid? loginId = null) => new(SessionStoreLoadStatus.Loaded, session, version, loginId);
    public static SessionStoreLoadResult Missing() => new(SessionStoreLoadStatus.Missing, null, SessionStoreVersion.Missing);
    public static SessionStoreLoadResult Cleared(SessionStoreVersion version) => new(SessionStoreLoadStatus.Cleared, null, version);
    public static SessionStoreLoadResult EmptyFile(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.EmptyFile, null, version);
    public static SessionStoreLoadResult DecryptFailed(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.DecryptFailed, null, version);
    public static SessionStoreLoadResult InvalidJson(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.InvalidJson, null, version);
    public static SessionStoreLoadResult SchemaMismatch(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.SchemaMismatch, null, version);
    public static SessionStoreLoadResult AuthorityMismatch(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.AuthorityMismatch, null, version);
    public static SessionStoreLoadResult SubjectMismatch(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.SubjectMismatch, null, version);
    public static SessionStoreLoadResult InvalidSession(SessionStoreVersion? version = null) => new(SessionStoreLoadStatus.InvalidSession, null, version);
    public static SessionStoreLoadResult IoFailure() => new(SessionStoreLoadStatus.IoFailure, null);
}

public enum SessionStoreWriteStatus
{
    Saved, Cleared, Conflict, InvalidRecord, InvalidSession, SchemaMismatch, AuthorityMismatch,
    SubjectMismatch, CryptoFailure, IoFailure
}

public sealed record SessionStoreWriteResult(SessionStoreWriteStatus Status, SessionStoreVersion? Version = null, Guid? LoginId = null)
{
    public bool Succeeded => Version is not null && (Status == SessionStoreWriteStatus.Cleared ||
        (Status == SessionStoreWriteStatus.Saved && LoginId is { } login && login != Guid.Empty));
    public static SessionStoreWriteResult Saved(SessionStoreVersion version, Guid loginId) => new(SessionStoreWriteStatus.Saved, version, loginId);
    public static SessionStoreWriteResult Cleared(SessionStoreVersion version) => new(SessionStoreWriteStatus.Cleared, version);
    public static SessionStoreWriteResult Conflict() => new(SessionStoreWriteStatus.Conflict);
    public static SessionStoreWriteResult InvalidRecord() => new(SessionStoreWriteStatus.InvalidRecord);
    public static SessionStoreWriteResult InvalidSession() => new(SessionStoreWriteStatus.InvalidSession);
    public static SessionStoreWriteResult SchemaMismatch() => new(SessionStoreWriteStatus.SchemaMismatch);
    public static SessionStoreWriteResult AuthorityMismatch() => new(SessionStoreWriteStatus.AuthorityMismatch);
    public static SessionStoreWriteResult SubjectMismatch() => new(SessionStoreWriteStatus.SubjectMismatch);
    public static SessionStoreWriteResult CryptoFailure() => new(SessionStoreWriteStatus.CryptoFailure);
    public static SessionStoreWriteResult IoFailure() => new(SessionStoreWriteStatus.IoFailure);
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
