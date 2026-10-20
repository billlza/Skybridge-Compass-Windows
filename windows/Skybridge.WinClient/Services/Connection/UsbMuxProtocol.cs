using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Skybridge.WinClient.Services.Connection;

internal sealed record UsbMuxDevice(uint DeviceId, string Udid, uint ProductId);
internal enum UsbMuxFailure { Malformed, DeviceUnavailable, AmbiguousDevice, PortUnavailable, ServiceRejected }
internal sealed class UsbMuxException(UsbMuxFailure failure) : IOException($"USB multiplex: {failure}")
{
    internal UsbMuxFailure Failure { get; } = failure;
}

/// <summary>Isolated bounded plist protocol candidate. USB routing records never establish
/// a protocol identity, account membership, pairing approval or audio permission.</summary>
internal static class UsbMuxProtocol
{
    internal const int MaximumPacketBytes = 1_048_576;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static XElement Request(string type) => Dictionary(
        ("MessageType", new XElement("string", type)),
        ("ClientVersionString", new XElement("string", "SkyBridge")),
        ("ProgName", new XElement("string", "SkyBridge")),
        ("kLibUSBMuxVersion", new XElement("integer", 3)));

    internal static XElement Dictionary(params (string Key, XElement Value)[] entries) =>
        new("dict", entries.SelectMany(e => new[] { new XElement("key", e.Key), e.Value }));

    internal static byte[] Packet(XElement dictionary, uint tag)
    {
        var document = new XDocument(new XDeclaration("1.0", "UTF-8", null),
            new XElement("plist", new XAttribute("version", "1.0"), new XElement(dictionary)));
        byte[] payload = Utf8.GetBytes(document.ToString(SaveOptions.DisableFormatting));
        if (payload.Length == 0 || payload.Length > MaximumPacketBytes - 16) throw Malformed();
        byte[] packet = new byte[16 + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(packet, checked((uint)packet.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(8), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(12), tag);
        payload.CopyTo(packet, 16);
        return packet;
    }

    internal static async Task<XElement> ReadAsync(Stream stream, uint tag, CancellationToken token)
    {
        byte[] header = new byte[16];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length < 17 || length > MaximumPacketBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4)) != 1 ||
            BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8)) != 8 ||
            BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12)) != tag) throw Malformed();
        byte[] payload = new byte[length - 16];
        await stream.ReadExactlyAsync(payload, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        return Parse(payload);
    }

    internal static XElement Parse(byte[] payload)
    {
        if (payload.Length == 0 || payload.Length > MaximumPacketBytes - 16) throw Malformed();
        // Standard plist documents have an external DOCTYPE. Ignore it without
        // resolving it; entity declarations must never provide hidden content.
        var settings = new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Ignore, XmlResolver = null,
            MaxCharactersInDocument = MaximumPacketBytes, MaxCharactersFromEntities = 1024,
            IgnoreComments = true, IgnoreProcessingInstructions = true
        };
        try
        {
            string text = Utf8.GetString(payload);
            using (var bounded = XmlReader.Create(new StringReader(text), settings))
            {
                int elements = 0;
                while (bounded.Read())
                    if (bounded.Depth > 16 ||
                        (bounded.NodeType == XmlNodeType.Element && ++elements > 8192)) throw Malformed();
            }
            using var reader = XmlReader.Create(new StringReader(text), settings);
            var document = XDocument.Load(reader, LoadOptions.None);
            var root = document.Root;
            if (root?.Name != "plist" || root.Attribute("version")?.Value != "1.0" ||
                root.Attributes().Count() != 1 || root.Elements().Count() != 1 ||
                root.Nodes().OfType<XText>().Any(n => !string.IsNullOrWhiteSpace(n.Value))) throw Malformed();
            var dictionary = root.Elements().Single();
            if (dictionary.Name != "dict") throw Malformed();
            ValidateValue(dictionary);
            return dictionary;
        }
        catch (Exception error) when (error is XmlException or DecoderFallbackException)
        { throw new InvalidDataException("Malformed USB multiplex plist.", error); }
    }

    private static void ValidateValue(XElement value)
    {
        if (value.HasAttributes || value.Name.Namespace != XNamespace.None) throw Malformed();
        switch (value.Name.LocalName)
        {
            case "dict":
                var entries = value.Elements().ToArray();
                if (entries.Length % 2 != 0 || value.Nodes().OfType<XText>().Any(n => !string.IsNullOrWhiteSpace(n.Value))) throw Malformed();
                var keys = new HashSet<string>(StringComparer.Ordinal);
                for (int i = 0; i < entries.Length; i += 2)
                {
                    var key = entries[i];
                    if (key.Name != "key" || key.HasAttributes || key.HasElements ||
                        key.Value.Length is < 1 or > 128 || !keys.Add(key.Value)) throw Malformed();
                    ValidateValue(entries[i + 1]);
                }
                break;
            case "array":
                if (value.Nodes().OfType<XText>().Any(n => !string.IsNullOrWhiteSpace(n.Value))) throw Malformed();
                foreach (var child in value.Elements()) ValidateValue(child);
                break;
            case "string": case "integer": case "data": case "real": case "date":
                if (value.HasElements) throw Malformed();
                break;
            case "true": case "false":
                if (value.HasElements || value.Value.Length != 0) throw Malformed();
                break;
            default: throw Malformed();
        }
    }

    internal static XElement Required(XElement dictionary, string key, string type)
    {
        if (dictionary.Name != "dict") throw Malformed();
        var entries = dictionary.Elements().ToArray();
        for (int i = 0; i < entries.Length; i += 2)
            if (entries[i].Value == key)
            {
                if (i + 1 >= entries.Length || entries[i + 1].Name != type) throw Malformed();
                return entries[i + 1];
            }
        throw Malformed();
    }

    internal static uint Integer(XElement dictionary, string key)
    {
        string value = Required(dictionary, key, "integer").Value;
        if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out uint result)) throw Malformed();
        return result;
    }

    internal static bool ValidUdid(string value) => value.Length is >= 24 and <= 64 &&
        value.All(c => char.IsAsciiHexDigit(c) || c == '-');

    internal static IReadOnlyList<UsbMuxDevice> Devices(XElement response)
    {
        var rows = Required(response, "DeviceList", "array").Elements().ToArray();
        if (rows.Length > 256) throw Malformed();
        var devices = new List<UsbMuxDevice>();
        var identifiers = new HashSet<uint>();
        var serials = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var properties = Required(row, "Properties", "dict");
            string connection = Required(properties, "ConnectionType", "string").Value;
            if (connection == "Network") continue;
            if (connection != "USB") throw Malformed();
            uint id = Integer(properties, "DeviceID"), product = Integer(properties, "ProductID");
            string udid = Required(properties, "SerialNumber", "string").Value;
            if (id == 0 || Integer(row, "DeviceID") != id || !ValidUdid(udid)) throw Malformed();
            if (!identifiers.Add(id) || !serials.Add(udid)) throw new UsbMuxException(UsbMuxFailure.AmbiguousDevice);
            devices.Add(new(id, udid, product));
        }
        return devices.OrderBy(d => d.Udid, StringComparer.Ordinal).ToArray();
    }

    internal static void RequireConnected(XElement response)
    {
        if (Required(response, "MessageType", "string").Value != "Result") throw Malformed();
        switch (Integer(response, "Number"))
        {
            case 0: return;
            case 2: throw new UsbMuxException(UsbMuxFailure.DeviceUnavailable);
            case 3: throw new UsbMuxException(UsbMuxFailure.PortUnavailable);
            default: throw new UsbMuxException(UsbMuxFailure.ServiceRejected);
        }
    }

    private static UsbMuxException Malformed() => new(UsbMuxFailure.Malformed);
}
