using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Skybridge.WinClient.Services;

/// <summary>Shared bare JSON framing and immutable Base64 bytes for PIB/SKR only.
/// Decoding an envelope does not validate its protocol body or grant authority.</summary>
internal static class LanBootstrapWire
{
    internal const int MaximumBytes = 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false, RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true, MaxDepth = 16,
        Converters = { new ImmutableBytesConverter() }
    };

    internal static T Decode<T>(ReadOnlySpan<byte> bytes, string discriminator)
    {
        using var document = ReadEnvelope(bytes);
        var property = document.RootElement.EnumerateObject().Single();
        if (property.Name != discriminator) throw new JsonException("Unexpected LAN bootstrap discriminator.");
        return property.Value.Deserialize<T>(Json) ?? throw new JsonException("LAN bootstrap payload is null.");
    }
    internal static string ReadDiscriminator(ReadOnlySpan<byte> bytes)
    {
        using var document = ReadEnvelope(bytes);
        return document.RootElement.EnumerateObject().Single().Name;
    }
    private static JsonDocument ReadEnvelope(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty || bytes.Length > MaximumBytes) throw new InvalidDataException("Invalid LAN bootstrap wire length.");
        // Reject invalid UTF-8 before JSON can replace it during string decoding.
        _ = Utf8.GetCharCount(bytes);
        var document = JsonSerializer.Deserialize<JsonDocument>(bytes, Json) ?? throw new JsonException("LAN bootstrap envelope is null.");
        try
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("LAN bootstrap envelope must be an object.");
            var properties = document.RootElement.EnumerateObject();
            if (!properties.MoveNext() || properties.Current.Value.ValueKind != JsonValueKind.Object)
                throw new JsonException("Invalid LAN bootstrap payload.");
            if (properties.MoveNext()) throw new JsonException("Ambiguous LAN bootstrap envelope.");
            return document;
        }
        catch { document.Dispose(); throw; }
    }
    internal static byte[] Encode<T>(string discriminator, T value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        { writer.WriteStartObject(); writer.WritePropertyName(discriminator); JsonSerializer.Serialize(writer, value, Json); writer.WriteEndObject(); }
        if (stream.Length > MaximumBytes) throw new InvalidDataException("LAN bootstrap exceeds its wire bound.");
        return stream.ToArray();
    }
    private sealed class ImmutableBytesConverter : JsonConverter<ImmutableArray<byte>>
    {
        public override ImmutableArray<byte> Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String) throw new JsonException("LAN bootstrap bytes must be Base64 text.");
            var value = reader.GetString() ?? throw new JsonException("LAN bootstrap bytes cannot be null.");
            if (value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))) throw new JsonException("Invalid LAN bootstrap Base64 alphabet.");
            var unpadded = value.TrimEnd('=');
            if (unpadded.Contains('=') || value.Length - unpadded.Length > 2 ||
                value.Length != unpadded.Length && value.Length % 4 != 0 || unpadded.Length % 4 == 1)
                throw new JsonException("Invalid LAN bootstrap Base64 padding.");
            try
            {
                var bytes = Convert.FromBase64String(unpadded.PadRight((unpadded.Length + 3) / 4 * 4, '='));
                if (Convert.ToBase64String(bytes).TrimEnd('=') != unpadded) throw new JsonException("Noncanonical LAN bootstrap Base64 bits.");
                return ImmutableArray.Create(bytes);
            }
            catch (FormatException error) { throw new JsonException("Invalid LAN bootstrap Base64 bytes.", error); }
        }
        public override void Write(Utf8JsonWriter writer, ImmutableArray<byte> value, JsonSerializerOptions options)
        {
            if (value.IsDefault) throw new JsonException("LAN bootstrap bytes are missing.");
            writer.WriteBase64StringValue(value.AsSpan());
        }
    }
}

internal static class LanBootstrapCanonical
{
    internal static long Milliseconds(double referenceSeconds)
    {
        var milliseconds = Math.Floor((referenceSeconds + 978_307_200.0) * 1000.0);
        if (!double.IsFinite(referenceSeconds) || !double.IsFinite(milliseconds) ||
            milliseconds < -9_223_372_036_854_775_808.0 || milliseconds >= 9_223_372_036_854_775_808.0)
            throw new InvalidDataException("LAN bootstrap timestamp is outside Int64 milliseconds.");
        return (long)milliseconds;
    }
    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string Trim(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        static bool Space(char c) => c is >= '\u0009' and <= '\u000d' or >= '\u001c' and <= '\u0020' or
            '\u00a0' or '\u1680' or >= '\u2000' and <= '\u200a' or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000';
        var start = 0; var end = value.Length;
        while (start < end && Space(value[start])) start++;
        while (end > start && Space(value[end - 1])) end--;
        return value[start..end];
    }

}
