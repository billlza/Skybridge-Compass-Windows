using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Xml.Linq;
using Skybridge.WinClient.Services;
using Skybridge.WinClient.Services.Audio;
using Skybridge.WinClient.Services.Connection;
using Skybridge.WinClient.Services.FileTransfer;

// Real MAIN encryption, mux framing and return TCP streams. Account evidence,
// USB discovery attestation and native output are controlled test boundaries.
internal static class AudioUsbFileReceiveTests
{
    internal static IEnumerable<(string Name, Func<Task> Run)> Cases =>
    [
        ("USB audio route codec preserves Apple opcode 17 and rejects zero or reserved fields", Wire),
        ("USB file capability requires the exact installed receiver and is withdrawn on unbind", Capability),
        ("USB original file returns through one mux port and preserves every rendered source byte", Complete),
        ("USB original file rejects wrong metadata and missing bound approval before granting bytes", Metadata),
        ("USB original file rejects a second port and closes the actual first return stream", DuplicatePort),
        ("USB original file account revocation retires a pending return stream", Revoked),
        ("USB original file cannot dial a return port before playback approval", Premature),
        ("USB file cancellation waits for actual return-stream release before publishing cleanup", DelayedRelease),
        ("USB file close failure retains the carrier owner and prevents playback or replacement", FailedRelease)
    ];
    private static void Require(bool value, string reason) { if (!value) throw new InvalidOperationException(reason); }
    private static async Task<T> Reject<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException($"Expected {typeof(T).Name}."); }
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static async Task Wire()
    {
        var stream = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        var bytes = AudioStreamingWire.Encode(new(stream, new AudioStreamingBody.UsbFileRoute(0x1234)));
        Require(Convert.ToHexStringLower(bytes) == "534241550111000000112233445566778899aabbccddeeff0000000412340000",
            "USB route differs from Apple's fixed header, UUID, port or reserved layout.");
        Require(AudioStreamingWire.Decode(bytes).Body is AudioStreamingBody.UsbFileRoute { Port: 0x1234 }, "USB route did not decode.");
        foreach (var change in new Action<byte[]>[] { b => { b[28] = 0; b[29] = 0; }, b => b[31] = 1, b => b[5] = 16 })
        {
            var altered = bytes.ToArray(); change(altered);
            await Reject<InvalidDataException>(() => Task.Run(() => AudioStreamingWire.Decode(altered)));
        }
    }
    private static async Task Capability()
    {
        await using var f = await Fixture.Create(bind: false);
        Require(!f.Registry.CanReceiveFor(f.Main.Lan.Session), "Uninstalled USB reception was available.");
        await Reject<InvalidOperationException>(() => f.Main.Lan.Session.SetAudioReceiverCapabilitiesAsync(true,
            AudioOriginalFileReceiveSupport.Wave, f.Token));
        var registration = f.Registry.BindUsb(f.Main.Lan.Session, f.Service.Connector, f.Root);
        using var consumerLifetime = CancellationTokenSource.CreateLinkedTokenSource(f.Token);
        var consumer = f.Main.Lan.Session.AcceptAudioOfferAsync(consumerLifetime.Token);
        try
        {
            await f.Main.Lan.Session.SetAudioReceiverCapabilitiesAsync(true, AudioOriginalFileReceiveSupport.Wave, f.Token, registration);
            var identity = LanProductControlMessages.Payload<LanProductIdentity>(await f.Main.Lan.Read());
            Require(identity.FileTransferPort is null && identity.Capabilities!.Contains(AudioStreamingWire.UsbFileReturnReceiveCapability) &&
                identity.Capabilities.Contains(ClassicFileTransferWire.ApprovalCapability), "Installed USB receiver advertised a TCP port or lost approval support.");
            await f.Registry.UnbindUsbAsync(f.Main.Lan.Session);
            Require(!registration.IsCurrentFor(f.Main.Lan.Session) && !f.Registry.CanReceiveFor(f.Main.Lan.Session), "Unbind retained USB authority.");
            await Reject<InvalidOperationException>(() => f.Main.Lan.Session.SetAudioReceiverCapabilitiesAsync(true,
                AudioOriginalFileReceiveSupport.Wave, f.Token, registration));
            Require(f.Service.Calls == 0, "Capability publication opened a file connection.");
        }
        finally { consumerLifetime.Cancel(); await Reject<OperationCanceledException>(() => consumer); }
    }
    private static async Task Complete()
    {
        await using var f = await Fixture.Create();
        await f.Offer(); await f.Return();
        await using (var network = new LanProductControlListener((_, _) => Task.CompletedTask, static () => true))
        {
            network.Start(IPAddress.Loopback, f.Token); f.Registry.Bind(network, f.Root);
            f.Registry.Unbind(network); // Network shutdown must not cancel the USB ticket.
        }
        await f.SendFile();
        Require((await f.Main.Read()).Body is AudioStreamingBody.OutputReady ready && ready.Format.SampleRate == 48000 &&
            ready.Format.Encoding == AudioStreamingEncoding.Float32 && ready.Format.ValidBits == 32, "USB changed PCM representation.");
        Require((await f.Main.Read()).Body is AudioStreamingBody.PlaybackComplete { SourceFrames: 25001, TrailingPaddingFrames: 0 },
            "USB file completion changed source extent.");
        var result = await f.Main.Run!.WaitAsync(f.Token);
        Require(result is AudioPlaybackReceiveReceipt.OriginalFile receipt && receipt.FileBytes == f.Bytes.Length &&
            receipt.FileSha256Hex == f.Metadata.FileHash && f.Main.Native.Submissions.SelectMany(b => b).SequenceEqual(f.Bytes.Skip(68)),
            "USB file receipt or rendered PCM changed the exact source bytes.");
        Require(f.Service.Calls == 2 && f.Service.Client!.Released && f.Service.Client.Disposals == 1,
            "USB return did not own exactly one enumeration and stream.");
        f.Released(); f.Main.NativeReleased(); await f.Main.Lan.Barrier();
    }
    private static async Task Metadata()
    {
        foreach (var change in new Func<ClassicFileMetadata, ClassicFileMetadata>[]
        {
            m => m with { TransferId = Guid.NewGuid().ToString("D") },
            m => m with { FileHash = new string('b',64) }, m => m with { ApprovalProtocol = null }
        })
        {
            await using var f = await Fixture.Create(); await f.Offer(); var stream = await f.Return();
            var metadata = ClassicFileTransferWire.Authenticate(change(f.Metadata), f.Key);
            await ClassicFileTransferFrames.WriteAsync(stream, ClassicFileFrameType.Metadata, ClassicFileTransferWire.Encode(metadata), f.Token);
            await f.Main.Failure();
            Require(await stream.ReadAsync(new byte[1], f.Token) == 0 && f.Main.Device.Activations == 0,
                "Wrong USB metadata received approval or opened output.");
            f.Released();
        }
    }
    private static async Task DuplicatePort()
    {
        await using var f = await Fixture.Create(); await f.Offer(); var stream = await f.Return();
        await f.Main.Lan.SendAudio(new(f.Main.StreamId, new AudioStreamingBody.UsbFileRoute(MuxService.Port)));
        var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.ProtocolViolation && f.Service.Calls == 2 &&
            await stream.ReadAsync(new byte[1], f.Token) == 0, "Repeated route opened another stream or left its first socket alive.");
        f.Released();
    }
    private static async Task Revoked()
    {
        await using var f = await Fixture.Create(); await f.Offer(); var stream = await f.Return();
        f.Main.Epoch.Revoke(); var failure = await f.Main.Failure();
        int remaining = await stream.ReadAsync(new byte[1], f.Token);
        Require(failure.Reason == AudioStreamingStopReason.AccountRevoked && remaining == 0 && f.Main.Device.Activations == 0,
            $"USB revocation result: reason={failure.Reason}; remaining={remaining}; activations={f.Main.Device.Activations}; cause={failure.Cause.GetType().Name}: {failure.Cause.Message}");
        f.Released();
    }
    private static async Task Premature()
    {
        await using var f = await Fixture.Create(); var entered = Signal();
        f.Main.Authorize = async (inbox, token) =>
        { entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token); return f.Main.Lease(inbox); };
        await f.StartOffer(); await entered.Task.WaitAsync(f.Token);
        await f.Main.Lan.SendAudio(new(f.Main.StreamId, new AudioStreamingBody.UsbFileRoute(MuxService.Port)));
        var failure = await f.Main.Failure();
        Require(failure.Reason == AudioStreamingStopReason.ProtocolViolation && f.Service.Calls == 0 &&
            f.Main.Device.Activations == 0, "A premature USB route reached a carrier or output effect.");
        f.Released();
    }
    private static async Task DelayedRelease()
    {
        await using var f = await Fixture.Create(); f.Service.BlockClose = true;
        await f.Offer(); await f.Return(); await f.SendFile();
        await f.Service.Client!.Closing.Task.WaitAsync(f.Token);
        Require(!f.Main.Run!.IsCompleted && f.Main.Device.Activations == 0, "Output began before USB close was confirmed.");
        f.Main.Caller.Cancel();
        Require(!f.Main.Run.IsCompleted, "Cancellation discarded an actual pending USB close.");
        f.Service.Client.Release.TrySetResult(); await f.Main.Failure();
        Require(f.Service.Client.Released && f.Service.Client.Disposals == 1, "Close was retried or never completed."); f.Released();
    }
    private static async Task FailedRelease()
    {
        await using var f = await Fixture.Create();
        var injected = new IOException("USB return test close failed."); f.Service.CloseFailure = injected;
        await f.Offer(); await f.Return(); await f.SendFile();
        var failure = await f.Main.Failure();
        Require(!failure.FileReleaseConfirmed && f.Main.Device.Activations == 0 &&
            failure.Cause is UsbMuxReleaseException retained && ReferenceEquals(retained.RetainedOwner, f.Service.Client) &&
            ReferenceEquals(retained.InnerException, injected), "USB close failure lost its real owner or allowed playback.");
        f.ExpectedUnbindFailure = await Reject<UsbMuxReleaseException>(() => f.Registry.UnbindUsbAsync(f.Main.Lan.Session));
        Require(!f.Registry.CanReceiveFor(f.Main.Lan.Session) && Directory.GetFiles(f.Root).Length == 0,
            "Failed USB close left a reusable receiver or private file.");
        await f.Service.Client!.HarnessClose(); // Test cleanup cannot change the product's failed release receipt.
        Require(!f.Main.Receiver.FileReleaseConfirmed, "Harness cleanup rewrote product cleanup evidence.");
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly string Root = Path.Combine(AppContext.BaseDirectory, "usb-audio-file-" + Guid.NewGuid().ToString("N"));
        internal readonly AudioOriginalFileReceiveRegistry Registry = new();
        internal readonly MuxService Service = new();
        internal AudioCaptureReceiveSessionTests.Fixture Main = null!;
        internal readonly Guid Transfer = Guid.NewGuid();
        internal readonly byte[] Bytes = AudioOriginalFileReceiveSessionTests.Wave(AudioOriginalFileReceiveSessionTests.Pcm(25001));
        internal byte[] Key = [];
        internal Exception? ExpectedUnbindFailure;
        internal CancellationToken Token => Main.Lan.Token;
        internal ClassicFileMetadata Metadata => ClassicFileTransferWire.Authenticate(new ClassicFileMetadata(Transfer.ToString("D"),
            "source.wav", Bytes.Length, Convert.ToHexStringLower(SHA256.HashData(Bytes)), 65536, 2,
            SenderDeviceId: Main.Lan.Session.PeerDeviceId, ApprovalProtocol: ClassicFileTransferWire.ApprovalProtocol), Key);
        internal static async Task<Fixture> Create(bool bind = true)
        {
            var f = new Fixture(); Directory.CreateDirectory(f.Root);
            var route = UsbControlRoute.From(LanProductControlSessionTests.UsbInspection());
            f.Main = await AudioCaptureReceiveSessionTests.Fixture.Create(f.Registry, null, carrier:
                new ProductControlCarrier.Usb(route, AudioAccountScope.From(AudioAccountMembershipTests.Authentication())));
            f.Main.Native.AllowRetirement = true;
            f.Key = ClassicFileTransferWire.DeriveTransferKey(f.Main.Lan.Keys, f.Transfer.ToString("D"));
            if (bind) f.Registry.BindUsb(f.Main.Lan.Session, f.Service.Connector, f.Root);
            return f;
        }
        internal async Task StartOffer()
        {
            Main.Run = Main.Receiver.RunAsync(Main.Caller.Token); await Main.Receiver.ReadyForOffer.WaitAsync(Token);
            await Main.Lan.SendAudio(new(Main.StreamId, new AudioStreamingBody.FileOffer(Transfer, Bytes.Length, SHA256.HashData(Bytes))));
        }
        internal async Task Offer()
        { await StartOffer(); Require((await Main.Read()).Body is AudioStreamingBody.Accept { ReceiveWindowBytes: 0 }, "USB file offer was not accepted."); }
        internal async Task<NetworkStream> Return()
        {
            await Main.Lan.SendAudio(new(Main.StreamId, new AudioStreamingBody.UsbFileRoute(MuxService.Port)));
            return await Service.File.Task.WaitAsync(Token);
        }
        internal async Task SendFile()
        {
            var stream = await Service.File.Task.WaitAsync(Token); var metadata = Metadata;
            await ClassicFileTransferFrames.WriteAsync(stream, ClassicFileFrameType.Metadata, ClassicFileTransferWire.Encode(metadata), Token);
            var grant = await ClassicFileTransferFrames.ReadAsync(stream, Token);
            Require(grant.Type == ClassicFileFrameType.Approval &&
                ClassicFileTransferWire.VerifyApproval(ClassicFileTransferWire.Decode<ClassicFileApproval>(grant.Payload), metadata, Key) is null,
                "USB sender did not receive exact metadata-bound permission before source bytes.");
            for (int offset = 0, index = 0; offset < Bytes.Length; offset += 65536, index++)
                await ClassicFileTransferFrames.WriteAsync(stream, ClassicFileFrameType.Chunk,
                    ClassicFileTransferWire.Encode(ClassicFileTransferWire.SealChunk(index, Bytes.AsSpan(offset, Math.Min(65536, Bytes.Length-offset)), Key)), Token);
            await ClassicFileTransferFrames.WriteAsync(stream, ClassicFileFrameType.Complete, ReadOnlyMemory<byte>.Empty, Token);
            var completed = await ClassicFileTransferFrames.ReadAsync(stream, Token);
            Require(completed.Type == ClassicFileFrameType.Receipt, "USB file transfer lost its separate final receipt.");
            var receipt = ClassicFileTransferWire.Decode<ClassicFileReceipt>(completed.Payload);
            ClassicFileTransferWire.Verify(receipt, metadata, Key); Require(receipt.Success, "USB file did not complete.");
        }
        internal void Released() => Require(Main.Receiver.FileReleaseConfirmed && Directory.GetFiles(Root).Length == 0,
            "USB file release was unconfirmed or left private content.");
        public async ValueTask DisposeAsync()
        {
            Service.Client?.Release.TrySetResult(); var failures = new List<Exception>();
            try { await Main.DisposeAsync(); } catch (Exception e) { failures.Add(e); }
            try { await Registry.UnbindUsbAsync(Main.Lan.Session); }
            catch (Exception e) when (ReferenceEquals(e, ExpectedUnbindFailure)) { }
            catch (Exception e) { failures.Add(e); }
            try { await Service.DisposeAsync(); } catch (Exception e) { failures.Add(e); }
            CryptographicOperations.ZeroMemory(Key);
            if (failures.Count != 0) throw new AggregateException("USB audio fixture cleanup failed.", failures);
            Require(Directory.GetFiles(Root).Length == 0, "Fixture cannot erase a leaked artifact."); Directory.Delete(Root);
        }
    }

    private sealed class MuxService : IAsyncDisposable
    {
        internal const ushort Port = 54321;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new(TimeSpan.FromSeconds(30));
        private readonly TaskCompletionSource _release = Signal();
        private readonly Task _run;
        private int _calls;
        internal int Calls => Volatile.Read(ref _calls);
        internal UsbMuxConnector Connector { get; }
        internal TaskCompletionSource<NetworkStream> File { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ReturnStream? Client;
        internal bool BlockClose;
        internal Exception? CloseFailure;
        internal MuxService()
        {
            _listener.Start();
            Connector = new(async token =>
            {
                int call = Interlocked.Increment(ref _calls);
                var stream = await UsbMuxConnector.ConnectSocket(_listener.LocalEndpoint, token);
                if (call == 2) { Client = new(stream, BlockClose, CloseFailure); return Client; }
                return stream;
            });
            _run = Run();
        }
        private async Task Run()
        {
            try
            {
                using (var client = await _listener.AcceptTcpClientAsync(_stop.Token))
                {
                    var stream = client.GetStream(); var request = await UsbMuxProtocol.ReadAsync(stream, 1, _stop.Token);
                    Require(UsbMuxProtocol.Required(request,"MessageType","string").Value == "ListDevices", "USB return did not enumerate its cable.");
                    var properties = UsbMuxProtocol.Dictionary(("DeviceID",new("integer",7)),("ProductID",new("integer",4779)),
                        ("SerialNumber",new("string","00008132-1111111111111111")),("ConnectionType",new("string","USB")));
                    await stream.WriteAsync(UsbMuxProtocol.Packet(UsbMuxProtocol.Dictionary(("DeviceList",new("array",
                        UsbMuxProtocol.Dictionary(("DeviceID",new("integer",7)),("Properties",properties))))),1),_stop.Token);
                }
                using (var client = await _listener.AcceptTcpClientAsync(_stop.Token))
                {
                    var stream=client.GetStream();var request=await UsbMuxProtocol.ReadAsync(stream,2,_stop.Token);
                    Require(UsbMuxProtocol.Required(request,"MessageType","string").Value=="Connect" &&
                        UsbMuxProtocol.Integer(request,"DeviceID")==7 && UsbMuxProtocol.Integer(request,"PortNumber")==BinaryPrimitives.ReverseEndianness(Port),
                        "USB return changed the selected device or port.");
                    await stream.WriteAsync(UsbMuxProtocol.Packet(UsbMuxProtocol.Dictionary(("MessageType",new("string","Result")),("Number",new("integer",0))),2),_stop.Token);
                    File.TrySetResult(stream); await _release.Task.WaitAsync(_stop.Token);
                }
            }
            catch (Exception e) { File.TrySetException(e); throw; }
        }
        public async ValueTask DisposeAsync()
        {
            _release.TrySetResult(); _stop.Cancel(); _listener.Stop();
            try { await _run; } catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            finally { _stop.Dispose(); }
        }
    }
    private sealed class ReturnStream(Stream inner, bool blockClose, Exception? closeFailure) : Stream
    {
        internal readonly TaskCompletionSource Closing = Signal(), Release = Signal();
        internal int Disposals; internal bool Released;
        public override bool CanRead=>inner.CanRead; public override bool CanWrite=>inner.CanWrite; public override bool CanSeek=>false;
        public override long Length=>throw new NotSupportedException(); public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override int Read(byte[] b,int o,int c)=>inner.Read(b,o,c); public override void Write(byte[] b,int o,int c)=>inner.Write(b,o,c);
        public override ValueTask<int> ReadAsync(Memory<byte>b,CancellationToken t=default)=>inner.ReadAsync(b,t);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte>b,CancellationToken t=default)=>inner.WriteAsync(b,t);
        public override void Flush()=>inner.Flush(); public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException();
        public override void SetLength(long v)=>throw new NotSupportedException();
        public override async ValueTask DisposeAsync()
        {
            Disposals++; Closing.TrySetResult(); if(blockClose)await Release.Task;
            if(closeFailure is not null)throw closeFailure;
            await inner.DisposeAsync(); Released=true;
        }
        internal ValueTask HarnessClose()=>inner.DisposeAsync();
    }
}
