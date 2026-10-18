using Skybridge.WinClient.Services.Audio;

internal static class ExclusivePcmOutputTests
{
    internal static readonly (string Name, Func<Task> Run)[] Cases =
    [
        Case("exclusive completion rechecks deadline and cancellation after its final authorization callback", TailFinalAuthorization),
        Case("exclusive tail completion cannot outlive its deadline during native cleanup", TailCleanupDeadline),
        Case("exclusive output rejects invalid or imprecise maximum-latency reports", LatencyBounds),
        Case("exclusive tail completion requires host time and device clock independently", TailBothClocks),
        Case("exclusive tail starts a fresh anchor after native observations return", TailFreshAnchor),
        Case("exclusive tail cannot complete on a stalled device clock or a truncated latency budget", TailStall),
        Case("exclusive tail retains device queue clock authority and cancellation failures", TailFailures),
        Case("exclusive tail receipt requires successful Stop and complete resource release", TailCleanupFailure),
        Case("exclusive tail rechecks revocation after native cleanup and handles empty input explicitly", TailDelivery),
        Case("exclusive output submits a short source tail without adding padding", ShortTail),
        Case("exact PCM writes the full extensible format including valid bits and layout", FormatBytes),
        Case("exact PCM rejects invalid and overflowing format declarations", InvalidFormats),
        Case("exclusive output rejects unsupported and closest-match formats", ExactSupportOnly),
        Case("non-event exclusive initialization does not retry or change output mode", InitializationFailure),
        Case("exclusive output validates native buffer capacity", InvalidNativeBuffers),
        Case("exclusive output preserves all raw sample bytes and offsets", RawBytes),
        Case("exclusive output requires prime and fresh capacity for each packet", BufferOrdering),
        Case("exclusive output rejects partial frames and oversize packets", PartialPacket),
        Case("exclusive finite output submits 480 plus 1 frames and distinguishes endpoint drain", FiniteTail),
        Case("exclusive endpoint drain cannot use elapsed device time while frames remain queued", DrainNotClockCompletion),
        Case("exclusive output clock discards imprecise readings with a finite retry bound", ClockAccuracy),
        Case("exclusive output rejects inconsistent device clock and queue reports", InvalidProgress),
        Case("exclusive output drain requires exact EOF and preserves empty-source semantics", FinishBoundaries),
        Case("exclusive output deadlines and cancellation cannot become drain success", DrainFailure),
        Case("native PCM packet bounds reject overrun and incomplete writes before buffer acquisition", NativePacketBounds),
        Case("native PCM packet writer pairs exact counts and discards only unsubmitted packets", NativePacketOwnership),
        Case("failed native submission does not advance accepted frame count", FailedSubmission),
        Case("output timeout and cancellation stop the current stream", WaitFailure),
        Case("output start failure stops and releases the attempted stream", StartFailure),
        Case("native already-stopped result preserves the original Start failure", AlreadyStoppedAfterStartFailure),
        Case("output ownership cannot cross worker threads", ThreadOwnership),
        Case("output stop and dispose preserve every cleanup error", CleanupErrors),
        Case("output initialization cleanup retains its primary error", OpenCleanupErrors),
        Case("output disposal is idempotent and cannot revive the client", TerminalDisposal)
    ];

    private static (string, Func<Task>) Case(string name, Action body) => (name, () => { body(); return Task.CompletedTask; });
    private static readonly ExactPcmFormat Stereo24 = new(44100, 2, 24, 24, false, 3);

    private static void TailFinalAuthorization()
    {
        foreach (bool cancel in new[] { true, false })
        {
            var clock = new Clock(); var client = new Client(); bool released = false;
            using var cancellation = new CancellationTokenSource();
            using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
            output.FinishInput(0); client.DisposeAction = () => released = true;
            void Complete() => output.CompleteAfterDeviceTail(TimeSpan.FromMilliseconds(100), cancellation.Token, () => {
                if (!released) return;
                if (cancel) cancellation.Cancel(); else clock.Advance(TimeSpan.FromSeconds(1));
            });
            if (cancel) Throws<OperationCanceledException>(Complete); else Throws<TimeoutException>(Complete);
            Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(1, client.DisposeCalls);
        }
    }

    private static void TailCleanupDeadline()
    {
        var clock = new Clock(); var client = new Client { Latency = 100_000 };
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
        output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1); client.Queued = 0;
        client.WaitAction = (delay, _) => { clock.Advance(delay); client.Position += 441; };
        client.DisposeAction = () => clock.Advance(TimeSpan.FromSeconds(1));
        Throws<TimeoutException>(() => output.CompleteAfterDeviceTail(TimeSpan.FromMilliseconds(100), default, () => { }));
        Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(1, client.DisposeCalls);
    }
    private static void LatencyBounds()
    {
        foreach (long latency in new[] { -1L, TimeSpan.FromSeconds(5).Ticks, long.MaxValue })
        {
            var client = new Client { Latency = latency }; var device = new Device(client);
            Throws<InvalidDataException>(() => ExclusivePcmOutput.Open(device, Stereo24, 441));
            Equal(0, client.PrepareCalls); Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
        }
        foreach (int result in new[] { 1, unchecked((int)0x80004005) })
        {
            var client = new Client { LatencyResult = result };
            Throws<IOException>(() => ExclusivePcmOutput.Open(new Device(client), Stereo24, 441));
            Equal(0, client.PrepareCalls); Equal(1, client.DisposeCalls);
        }
    }
    private static void TailBothClocks()
    {
        foreach (bool fastDevice in new[] { true, false })
        {
            var clock = new Clock(); var client = new Client { Latency = 100_000, Frequency = 192000 }; var device = new Device(client);
            using var output = ExclusivePcmOutput.Open(device, Stereo24, 441, clock);
            output.Submit(new byte[17 * 6], 0, 17 * 6); output.Start(); output.FinishInput(17);
            client.Queued = 0; client.Position = 1_000_000; // An old large position cannot finish the later source tail.
            client.WaitAction = (delay, _) => {
                Equal(0, client.StopCalls);
                clock.Advance(fastDevice ? delay : delay * 2);
                client.Position += (ulong)(delay.Ticks * (long)client.Frequency / TimeSpan.TicksPerSecond) * (fastDevice ? 2UL : 1UL);
            };
            var receipt = output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(1), default, () => { });
            var tail = receipt.Tail ?? throw new Exception("Missing nonempty tail observation.");
            Equal(17UL, receipt.SourceFrames); Equal(1_000_000UL, tail.AnchorDevicePosition);
            Equal(4, client.WaitCalls); Check(tail.HostElapsed.Ticks >= 100_000, "Device clock replaced host elapsed time.");
            Check((UInt128)(tail.FinalDevicePosition - tail.AnchorDevicePosition) * TimeSpan.TicksPerSecond >= (UInt128)100_000 * tail.DeviceFrequency,
                "Host elapsed time replaced device progress.");
            Equal(1, client.StopCalls); Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
            Equal(ExclusivePcmOutputState.Completed, output.State);
        }
    }
    private static void TailFreshAnchor()
    {
        var clock = new Clock(); var client = new Client { Latency = 100_000, Frequency = 192000 };
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
        output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1); client.Queued = 0;
        _ = output.WaitForEndpointDrain(TimeSpan.FromSeconds(1), default);
        bool first = true;
        client.ClockAction = () => { if (first) { first = false; clock.Advance(TimeSpan.FromMilliseconds(50)); client.Position = 50_000; } };
        client.WaitAction = (delay, _) => { clock.Advance(delay); client.Position += 480; };
        var receipt = output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(1), default, () => { });
        Equal(4, client.WaitCalls); Equal(50_000UL, receipt.Tail!.AnchorDevicePosition);
        Equal(TimeSpan.FromMilliseconds(10), receipt.Tail.HostElapsed);
    }
    private static void TailStall()
    {
        foreach (long latency in new[] { 0L, 100_000L, 400_000L })
        {
            var clock = new Clock(); var client = new Client { Latency = latency };
            using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
            output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1); client.Queued = 0; client.Position = 9999;
            client.WaitAction = (delay, _) => clock.Advance(delay);
            Throws<TimeoutException>(() => output.CompleteAfterDeviceTail(TimeSpan.FromMilliseconds(30), default, () => { }));
            Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(1, client.StopCalls);
        }
    }
    private static void TailFailures()
    {
        foreach (string mode in new[] { "frequency", "backwards", "imprecise", "padding", "latency", "native", "canceled", "revoked" })
        {
            var clock = new Clock(); var client = new Client { Latency = 100_000, Frequency = 192000 };
            using var canceled = new CancellationTokenSource(); bool revoked = false;
            using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
            output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1); client.Queued = 0; client.Position = 100;
            client.WaitAction = (delay, _) => {
                clock.Advance(delay); client.Position += 480;
                if (client.WaitCalls != 1) return;
                switch (mode)
                {
                    case "frequency": client.Frequency++; break;
                    case "backwards": client.Position = 99; break;
                    case "imprecise": for (int i = 0; i < 3; i++) client.ClockReads.Enqueue((1, 900, 0)); break;
                    case "padding": client.Queued = 1; break;
                    case "latency": client.Latency = 200_000; break;
                    case "native": client.ClockReads.Enqueue((unchecked((int)0x80004005), 0, 0)); break;
                    case "canceled": canceled.Cancel(); break;
                    case "revoked": revoked = true; break;
                }
            };
            void Complete() => output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(1), canceled.Token,
                () => { if (revoked) throw new InvalidOperationException("approval revoked"); });
            if (mode == "canceled") Throws<OperationCanceledException>(Complete);
            else if (mode == "revoked") Throws<InvalidOperationException>(Complete);
            else if (mode is "frequency" or "backwards" or "padding" or "latency") Throws<InvalidDataException>(Complete);
            else Throws<IOException>(Complete);
            Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(1, client.StopCalls);
        }
    }
    private static void TailCleanupFailure()
    {
        var clock = new Clock(); var client = new Client { Latency = 0 };
        var device = new Device(client); var output = ExclusivePcmOutput.Open(device, Stereo24, 441, clock);
        output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1); client.Queued = 0;
        client.WaitAction = (delay, _) => { clock.Advance(delay); client.Position++; };
        var stop = new IOException("Stop failed"); var close = new IOException("client close failed"); var release = new IOException("device close failed");
        client.StopFailure = stop; client.DisposeFailure = close; device.DisposeFailure = release;
        var error = Throws<AggregateException>(() => output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(1), default, () => { }));
        foreach (var cause in new[] { stop, close, release }) Check(error.Flatten().InnerExceptions.Contains(cause), "Tail completion lost a cleanup failure.");
        Equal(ExclusivePcmOutputState.CleanupFailed, output.State); Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
        Throws<AggregateException>(output.Dispose); Equal(1, client.DisposeCalls);
    }
    private static void TailDelivery()
    {
        foreach (bool cancel in new[] { true, false })
        {
            var clock = new Clock(); var client = new Client(); bool revoked = false;
            using var cancellation = new CancellationTokenSource();
            using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
            output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1); client.Queued = 0;
            client.WaitAction = (delay, _) => { clock.Advance(delay); client.Position++; };
            client.DisposeAction = () => { if (cancel) cancellation.Cancel(); else revoked = true; };
            void Complete() => output.CompleteAfterDeviceTail(TimeSpan.FromSeconds(1), cancellation.Token,
                () => { if (revoked) throw new InvalidOperationException("revoked during native close"); });
            if (cancel) Throws<OperationCanceledException>(Complete); else Throws<InvalidOperationException>(Complete);
            Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(1, client.DisposeCalls);
        }
        var empty = new Client(); using var outputEmpty = ExclusivePcmOutput.Open(new Device(empty), Stereo24, 441);
        outputEmpty.FinishInput(0);
        var receipt = outputEmpty.CompleteAfterDeviceTail(TimeSpan.FromSeconds(1), default, () => { });
        Equal(0UL, receipt.SourceFrames); Check(receipt.Tail is null, "Empty stream invented device playback evidence.");
        Equal(0, empty.StartCalls); Equal(0, empty.WaitCalls); Equal(1, empty.DisposeCalls);
    }

    private static void ShortTail()
    {
        var client = new Client { Frames = 480 };
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 480);
        var source = Enumerable.Range(0, 17 * Stereo24.BytesPerFrame).Select(i => (byte)i).ToArray();
        output.Submit(source, 0, source.Length);
        Equal(17UL, output.SubmittedFrames);
        Check(client.Submissions.Single().SequenceEqual(source), "Short source tail was padded or changed.");
    }

    private static void FormatBytes()
    {
        Equal("FEFF020044AC0000980904000600180016001800030000000100000000001000800000AA00389B71",
            Convert.ToHexString(Stereo24.ToWaveFormatExtensible()));
        var format = new ExactPcmFormat(96000, 2, 32, 24, false, 0);
        var bytes = format.ToWaveFormatExtensible();
        Equal((byte)32, bytes[14]); Equal((byte)24, bytes[18]);
        Check(bytes.AsSpan(20, 4).SequenceEqual(new byte[4]), "Explicit DIRECTOUT layout changed.");
        var floating = new ExactPcmFormat(48000, 2, 32, 32, true, 3).ToWaveFormatExtensible();
        Equal((byte)3, floating[24]); Equal((byte)32, floating[18]);
        Equal(108844L, ExclusivePcmOutput.PeriodForFrames(Stereo24, 480));
    }

    private static void InvalidFormats()
    {
        Throws<ArgumentException>(() => new ExactPcmFormat(0, 2, 24, 24, false, 3));
        Throws<ArgumentException>(() => new ExactPcmFormat(44100, 0, 24, 24, false, 3));
        Throws<ArgumentException>(() => new ExactPcmFormat(44100, 2, 20, 20, false, 3));
        Throws<ArgumentException>(() => new ExactPcmFormat(44100, 2, 32, 0, false, 3));
        Throws<ArgumentException>(() => new ExactPcmFormat(44100, 2, 32, 24, true, 3));
        Throws<ArgumentException>(() => new ExactPcmFormat(44100, 2, 24, 24, true, 3));
        Throws<OverflowException>(() => new ExactPcmFormat(uint.MaxValue, 2, 32, 32, false, 3));
        Throws<OverflowException>(() => new ExactPcmFormat(1, ushort.MaxValue, 64, 64, true, 0));
        Throws<InvalidDataException>(() => ExclusivePcmOutput.PeriodForFrames(Stereo24, 0));
        Throws<InvalidDataException>(() => ExclusivePcmOutput.PeriodForFrames(Stereo24, 44101));
        Throws<InvalidDataException>(() => ExclusivePcmOutput.PeriodForFrames(new(100_000_000, 1, 8, 8, false, 0), 1));
    }

    private static void ExactSupportOnly()
    {
        foreach (var result in new[] { 1, unchecked((int)0x88890008), unchecked((int)0x80004005) })
        {
            var client = new Client { SupportResult = result };
            var device = new Device(client);
            Throws<IOException>(() => ExclusivePcmOutput.Open(device, Stereo24, 441));
            Equal(0, client.InitializeCalls); Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
        }
    }

    private static void InitializationFailure()
    {
        foreach (var result in new[] { unchecked((int)0x88890019), unchecked((int)0x8889000A), 1 })
        {
            var client = new Client { InitializeResult = result }; var device = new Device(client);
            Throws<IOException>(() => ExclusivePcmOutput.Open(device, Stereo24, 441));
            Equal(1, device.Activations); Equal(1, client.InitializeCalls); Equal(0, client.PrepareCalls);
            Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
        }
        var larger = new Client { Frames = 480 };
        using var output = ExclusivePcmOutput.Open(new Device(larger), Stereo24, 441);
        Equal(100000L, larger.Period); Equal(480U, output.BufferFrames);
        Check(ReferenceEquals(larger.Format, Stereo24), "Actual buffer sizing changed source format.");
    }

    private static void InvalidNativeBuffers()
    {
        foreach (var frames in new[] { 0U, 440U, 44101U, uint.MaxValue })
        {
            var client = new Client { Frames = frames };
            var device = new Device(client);
            Throws<InvalidDataException>(() => ExclusivePcmOutput.Open(device, Stereo24, 441));
            Equal(0, client.PrepareCalls); Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
        }
        var huge = new ExactPcmFormat(192000, 8, 64, 64, true, 0);
        var largeDevice = new Device(new Client { Frames = 192000 });
        Throws<InvalidDataException>(() => ExclusivePcmOutput.Open(largeDevice, huge, 192000));
        Equal(0, largeDevice.Activations); Equal(1, largeDevice.DisposeCalls);
    }

    private static void RawBytes()
    {
        foreach (var format in new[] { Stereo24, new ExactPcmFormat(192000, 2, 32, 24, false, 3),
            new ExactPcmFormat(48000, 2, 32, 32, true, 3), new ExactPcmFormat(96000, 2, 64, 64, true, 3) })
        {
            var client = new Client { Frames = 16 };
            using var output = ExclusivePcmOutput.Open(new Device(client), format, 16);
            var bytes = Enumerable.Range(0, output.BufferBytes + 10).Select(i => (byte)((i * 137 + 23) & 255)).ToArray();
            var expected = bytes.AsSpan(5, output.BufferBytes).ToArray();
            output.Submit(bytes, 5, output.BufferBytes);
            Check(client.Submissions.Single().SequenceEqual(expected), "Raw PCM bits were altered.");
            Equal(16UL, output.SubmittedFrames); Equal(ExclusivePcmOutputState.Primed, output.State);
            output.Start();
            output.WaitForBuffer(TimeSpan.FromSeconds(1), CancellationToken.None);
            output.Submit(bytes, 5, output.BufferBytes);
            Equal(32UL, output.SubmittedFrames);
            output.Stop();
            Equal(ExclusivePcmOutputState.Stopped, output.State);
            Equal(32UL, output.SubmittedFrames); // Stop is not a claim that these frames were heard.
        }
    }

    private static void BufferOrdering()
    {
        var client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        { Throws<InvalidOperationException>(output.Start); Equal(0, client.StartCalls); }
        client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        {
            var bytes = new byte[output.BufferBytes]; output.Submit(bytes, 0, bytes.Length); output.Start();
            Throws<InvalidOperationException>(() => output.Submit(bytes, 0, bytes.Length));
            Equal(1, client.Submissions.Count); Equal(1, client.StopCalls);
        }
        client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        {
            var bytes = new byte[output.BufferBytes]; output.Submit(bytes, 0, bytes.Length); output.Start();
            Equal(441U, output.WaitForBuffer(TimeSpan.FromSeconds(1), default));
            output.Submit(bytes, 0, 6);
            Throws<InvalidOperationException>(() => output.Submit(bytes, 0, bytes.Length));
            Equal(442UL, output.SubmittedFrames); Equal(2, client.Submissions.Count); Equal(1, client.WaitCalls);
        }
    }
    private static void PartialPacket()
    {
        foreach (var difference in new[] { -1, 1, 6 })
        {
            var client = new Client(); using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
            var bytes = new byte[output.BufferBytes + difference];
            Throws<ArgumentException>(() => output.Submit(bytes, 0, bytes.Length));
            Equal(0, client.Submissions.Count); Equal(0UL, output.SubmittedFrames); Equal(ExclusivePcmOutputState.Faulted, output.State);
        }
    }
    private static void FiniteTail()
    {
        var client = new Client { Frames = 480 }; using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 480);
        var bytes = Enumerable.Range(0, 481 * 6 + 3).Select(i => (byte)(i * 17)).ToArray();
        output.Submit(bytes, 3, 480 * 6); output.Start(); output.WaitForBuffer(TimeSpan.FromSeconds(1), default);
        output.Submit(bytes, 3 + 480 * 6, 6); output.FinishInput(481);
        var receipt = output.WaitForEndpointDrain(TimeSpan.FromSeconds(1), default);
        Equal(481UL, output.SubmittedFrames); Equal(481UL, receipt.SourceFrames);
        Check(client.PacketFrames.SequenceEqual(new uint[] { 480, 1 }), "Tail packet changed native request/release frame count.");
        Check(client.Submissions.SelectMany(packet => packet).SequenceEqual(bytes.Skip(3)), "Finite source bytes were padded, dropped or repacked.");
        Equal(0, client.StopCalls); Equal(ExclusivePcmOutputState.EndpointDrained, output.State);
        output.Stop(); Equal(1, client.StopCalls); Equal(ExclusivePcmOutputState.Stopped, output.State);
    }
    private static void DrainNotClockCompletion()
    {
        var client = new Client { Frames = 480, Frequency = 192000 };
        using var output = ExclusivePcmOutput.Open(new Device(client), new(48000, 2, 16, 16, false, 3), 480);
        output.Submit(new byte[1920], 0, 1920); output.Start(); client.Position = 4800; output.FinishInput(480);
        client.WaitAction = (_, _) => { if (client.WaitCalls == 2) client.Queued = 0; };
        var receipt = output.WaitForEndpointDrain(TimeSpan.FromSeconds(1), default);
        Equal(2, client.WaitCalls); Equal(4800UL, receipt.DevicePosition); Equal(192000UL, receipt.DeviceFrequency);
        Equal(0.025m, (decimal)receipt.DevicePosition / receipt.DeviceFrequency);
        Equal(0, client.StopCalls); // A high clock value plus drain still does not announce source playback completion.
    }
    private static void ClockAccuracy()
    {
        var client = new Client(); using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
        output.Submit(new byte[6], 0, 6);
        client.ClockReads.Enqueue((1, ulong.MaxValue, 0)); client.ClockReads.Enqueue((0, 0, 44100)); output.Start();
        Equal(2, client.ClockCalls);
        client.ClockReads.Enqueue((1, 900, 1)); client.ClockReads.Enqueue((0, 1, 44100));
        Equal(1UL, output.ObserveProgress().DevicePosition);
        for (int i = 0; i < 3; i++) client.ClockReads.Enqueue((1, ulong.MaxValue, 0));
        Throws<IOException>(() => output.ObserveProgress()); Equal(7, client.ClockCalls); Equal(1, client.StopCalls);
    }
    private static void InvalidProgress()
    {
        foreach (string mode in new[] { "capacity", "submitted", "retired", "frequency-zero", "frequency-change", "clock-backwards", "clock-error", "clock-other-success" })
        {
            var client = new Client(); using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
            output.Submit(new byte[12], 0, 12); output.Start();
            client.Queued = 1; client.Position = 1; _ = output.ObserveProgress();
            switch (mode)
            {
                case "capacity": client.Queued = 442; break;
                case "submitted": client.Queued = 3; break;
                case "retired": client.Queued = 2; break;
                case "frequency-zero": client.Frequency = 0; break;
                case "frequency-change": client.Frequency = 48000; break;
                case "clock-backwards": client.Position = 0; break;
                case "clock-error": client.ClockReads.Enqueue((unchecked((int)0x80004005), 0, 0)); break;
                case "clock-other-success": client.ClockReads.Enqueue((2, 0, 0)); break;
            }
            if (mode.StartsWith("clock-", StringComparison.Ordinal) && mode != "clock-backwards") Throws<IOException>(() => output.ObserveProgress());
            else Throws<InvalidDataException>(() => output.ObserveProgress());
            Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(2UL, output.SubmittedFrames);
        }
    }
    private static void FinishBoundaries()
    {
        var client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        {
            output.FinishInput(0); var receipt = output.WaitForEndpointDrain(TimeSpan.FromSeconds(1), default);
            Equal(0UL, receipt.SourceFrames); Equal(0, client.StartCalls);
        }
        client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        { output.Submit(new byte[6], 0, 6); Throws<InvalidOperationException>(() => output.FinishInput(2)); }
        client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        { output.Submit(new byte[6], 0, 6); output.FinishInput(1); output.Start(); Throws<InvalidOperationException>(() => output.Submit(new byte[6], 0, 6)); }
        client = new Client();
        using (var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441))
        { output.Submit(new byte[6], 0, 6); output.Start(); Throws<InvalidOperationException>(() => output.WaitForEndpointDrain(TimeSpan.FromSeconds(1), default)); }
    }
    private sealed class Clock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        internal void Advance(TimeSpan delay) => _ticks += delay.Ticks;
    }
    private static void DrainFailure()
    {
        foreach (string mode in new[] { "deadline", "cancel-after-query", "deadline-after-query", "native-failure" })
        {
            var clock = new Clock(); var client = new Client(); using var canceled = new CancellationTokenSource();
            using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441, clock);
            output.Submit(new byte[6], 0, 6); output.Start(); output.FinishInput(1);
            if (mode == "deadline") client.WaitAction = (delay, _) => clock.Advance(delay);
            if (mode == "cancel-after-query") client.PaddingAction = () => { client.Queued = 0; canceled.Cancel(); };
            if (mode == "deadline-after-query") client.PaddingAction = () => { client.Queued = 0; clock.Advance(TimeSpan.FromSeconds(1)); };
            if (mode == "native-failure") client.PaddingAction = () => throw new IOException("device invalidated after final write");
            if (mode == "cancel-after-query") Throws<OperationCanceledException>(() => output.WaitForEndpointDrain(TimeSpan.FromMilliseconds(10), canceled.Token));
            else if (mode == "native-failure") Throws<IOException>(() => output.WaitForEndpointDrain(TimeSpan.FromMilliseconds(10), default));
            else Throws<TimeoutException>(() => output.WaitForEndpointDrain(TimeSpan.FromMilliseconds(10), default));
            Equal(ExclusivePcmOutputState.Faulted, output.State); Equal(1, client.StopCalls);
        }
    }

    private static void FailedSubmission()
    {
        var client = new Client();
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
        var bytes = new byte[output.BufferBytes];
        output.Submit(bytes, 0, bytes.Length); output.Start();
        output.WaitForBuffer(TimeSpan.FromSeconds(1), CancellationToken.None);
        var failure = new IOException("release buffer failed"); client.SubmitFailure = failure;
        Check(ReferenceEquals(failure, Throws<IOException>(() => output.Submit(bytes, 0, bytes.Length))), "Submission failure was replaced.");
        Equal(441UL, output.SubmittedFrames); Equal(1, client.StopCalls);
        Equal(1, client.DisposeCalls);
        Equal(ExclusivePcmOutputState.Faulted, output.State);
    }

    private static void WaitFailure()
    {
        foreach (var failure in new Exception[] { new TimeoutException("device stalled"), new OperationCanceledException() })
        {
            var client = new Client { WaitFailure = failure };
            using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
            output.Submit(new byte[output.BufferBytes], 0, output.BufferBytes); output.Start();
            Check(ReferenceEquals(failure, Throws<Exception>(() => output.WaitForBuffer(TimeSpan.FromSeconds(1), CancellationToken.None))), "Wait failure changed.");
            Equal(1, client.StopCalls); Equal(441UL, output.SubmittedFrames);
            Equal(ExclusivePcmOutputState.Faulted, output.State);
        }
    }

    private static void StartFailure()
    {
        var client = new Client { StartFailure = new IOException("device invalidated") };
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
        output.Submit(new byte[output.BufferBytes], 0, output.BufferBytes);
        Throws<IOException>(output.Start);
        Equal(1, client.StopCalls); Equal(ExclusivePcmOutputState.Faulted, output.State);
    }

    private static void ThreadOwnership()
    {
        var client = new Client();
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
        Exception? observed = null;
        var thread = new Thread(() => { try { output.Dispose(); } catch (Exception error) { observed = error; } });
        thread.Start(); Check(thread.Join(TimeSpan.FromSeconds(3)), "Worker did not terminate.");
        Check(observed is InvalidOperationException, "Foreign worker disposed native resources.");
        Equal(0, client.DisposeCalls); Equal(ExclusivePcmOutputState.Initialized, output.State);
    }
    private static void AlreadyStoppedAfterStartFailure()
    {
        var primary = new IOException("native Start failed before running");
        var client = new Client { StartFailure = primary, StopResult = 1 };
        using var output = ExclusivePcmOutput.Open(new Device(client), Stereo24, 441);
        output.Submit(new byte[6], 0, 6);
        Check(ReferenceEquals(primary, Throws<IOException>(output.Start)), "Legal S_FALSE Stop turned Start failure into a cleanup failure.");
        Equal(1, client.StopCalls); Equal(1, client.DisposeCalls); Equal(ExclusivePcmOutputState.Faulted, output.State);
        Check(output.CleanupFailure is null, "Released native owner was reported as unconfirmed.");
        Throws<IOException>(() => ExclusivePcmOutput.RequireStopped(2));
        Throws<IOException>(() => ExclusivePcmOutput.RequireStopped(unchecked((int)0x80004005)));
    }

    private static void CleanupErrors()
    {
        var client = new Client { StopFailure = new IOException("stop"), DisposeFailure = new IOException("client release") };
        var device = new Device(client) { DisposeFailure = new IOException("device release") };
        var output = ExclusivePcmOutput.Open(device, Stereo24, 441);
        output.Submit(new byte[output.BufferBytes], 0, output.BufferBytes); output.Start();
        var failure = Throws<AggregateException>(output.Dispose);
        Equal(3, failure.InnerExceptions.Count); Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls);
        Check(ReferenceEquals(failure, Throws<AggregateException>(output.Dispose)), "Cleanup failure disappeared on repeated close.");
        Equal(ExclusivePcmOutputState.CleanupFailed, output.State);
        Check(ReferenceEquals(failure, output.CleanupFailure), "Cleanup failure is not observable.");
        Equal(1, client.DisposeCalls);
    }

    private static void OpenCleanupErrors()
    {
        var primary = new IOException("prepare");
        var client = new Client { PrepareFailure = primary, DisposeFailure = new IOException("client release") };
        var device = new Device(client) { DisposeFailure = new IOException("device release") };
        var failure = Throws<ExclusivePcmOpenCleanupException>(() => ExclusivePcmOutput.Open(device, Stereo24, 441));
        Equal(3, failure.InnerExceptions.Count); Check(ReferenceEquals(primary, failure.InnerExceptions[0]), "Primary open failure lost.");
        Check(ReferenceEquals(device, failure.RetainedDevice) && ReferenceEquals(client, failure.RetainedClient),
            "Unconfirmed open cleanup discarded its actual native owners.");
    }

    private static void TerminalDisposal()
    {
        var client = new Client(); var device = new Device(client);
        var output = ExclusivePcmOutput.Open(device, Stereo24, 441);
        output.Dispose(); output.Dispose(); output.Stop();
        Throws<ObjectDisposedException>(output.Start);
        Throws<ObjectDisposedException>(() => output.Submit(new byte[2646], 0, 2646));
        Equal(ExclusivePcmOutputState.Disposed, output.State);
        Equal(1, client.DisposeCalls); Equal(1, device.DisposeCalls); Equal(0, client.StartCalls);
    }

    private static void NativePacketBounds()
    {
        ExclusivePcmPacketBounds.Validate(2656, 5, 2646, 441, 441, 6);
        Throws<ArgumentException>(() => ExclusivePcmPacketBounds.Validate(3000, 0, 2647, 441, 441, 6));
        Throws<ArgumentException>(() => ExclusivePcmPacketBounds.Validate(3000, 0, 2645, 441, 441, 6));
        ExclusivePcmPacketBounds.Validate(3000, 0, 2640, 440, 441, 6);
        ExclusivePcmPacketBounds.Validate(6, 0, 6, 1, 441, 6);
        Throws<ArgumentException>(() => ExclusivePcmPacketBounds.Validate(3000, 0, 2652, 442, 441, 6));
        Throws<ArgumentException>(() => ExclusivePcmPacketBounds.Validate(2646, 1, 2646, 441, 441, 6));
        Throws<ArgumentException>(() => ExclusivePcmPacketBounds.Validate(2646, -1, 2646, 441, 441, 6));
        Throws<ArgumentException>(() => ExclusivePcmPacketBounds.Validate(int.MaxValue, 0, int.MaxValue, uint.MaxValue, uint.MaxValue, 8));
    }

    private sealed class PacketPort : IExclusivePcmPacketPort
    {
        internal string Mode = "success";
        internal readonly List<uint> Acquired = [], Released = [];
        internal byte[]? Copied;
        internal readonly IOException Failure = new("fixture packet failure");
        public IntPtr Acquire(uint frames)
        {
            if (Mode == "acquire-fails") throw Failure;
            Acquired.Add(frames); return Mode == "null-buffer" ? IntPtr.Zero : new IntPtr(1);
        }
        public void Copy(byte[] bytes, int offset, IntPtr destination, int count)
        {
            if (Mode is "copy-fails" or "discard-fails") throw Failure;
            Copied = bytes.AsSpan(offset, count).ToArray();
        }
        public void Release(uint frames)
        { Released.Add(frames); if (Mode is "release-fails" or "discard-fails") throw new IOException("fixture release failure"); }
    }
    private static void NativePacketOwnership()
    {
        var source = Enumerable.Range(0, 12).Select(value => (byte)value).ToArray();
        var success = new PacketPort(); ExclusivePcmPacketWriter.Write(success, source, 3, 6, 1);
        Check(success.Acquired.SequenceEqual(new uint[] { 1 }) && success.Released.SequenceEqual(new uint[] { 1 }) &&
            success.Copied!.SequenceEqual(source.Skip(3).Take(6)), "Native tail changed bytes or Get/Release frame counts.");
        foreach (var mode in new[] { "acquire-fails", "null-buffer", "copy-fails", "discard-fails", "release-fails" })
        {
            var port = new PacketPort { Mode = mode };
            if (mode == "discard-fails")
            {
                var error = Throws<AggregateException>(() => ExclusivePcmPacketWriter.Write(port, source, 0, 6, 1));
                Equal(2, error.InnerExceptions.Count); Check(ReferenceEquals(port.Failure, error.InnerExceptions[0]), "Primary copy failure disappeared.");
            }
            else Throws<IOException>(() => ExclusivePcmPacketWriter.Write(port, source, 0, 6, 1));
            var expected = mode == "acquire-fails" ? Array.Empty<uint>() : new uint[] { mode == "release-fails" ? 1U : 0U };
            Check(port.Released.SequenceEqual(expected), "Native packet was double-released, silently submitted, or left undiscarded.");
        }
    }

    private sealed class Device(params Client[] clients) : IExclusivePcmDevice
    {
        public int Activations, DisposeCalls;
        public Exception? DisposeFailure;
        public IExclusivePcmClient Activate() => clients[Activations++];
        public void Dispose() { DisposeCalls++; if (DisposeFailure is not null) throw DisposeFailure; }
    }

    // Models the native boundary. These tests do not run WASAPI or prove physical playback.
    private sealed class Client : IExclusivePcmClient
    {
        public int SupportResult, InitializeResult, InitializeCalls, PrepareCalls, StartCalls, WaitCalls, StopCalls, DisposeCalls, ClockCalls, StopResult, LatencyResult;
        public uint Frames = 441, Queued;
        public ulong Position, Frequency = 44100;
        public Action<TimeSpan, CancellationToken>? WaitAction;
        public Action? PaddingAction, ClockAction, DisposeAction;
        public Queue<(int Result, ulong Position, ulong Frequency)> ClockReads { get; } = new();
        public List<uint> PacketFrames { get; } = [];
        public long Period, Latency;
        public ExactPcmFormat? Format;
        public Exception? PrepareFailure, SubmitFailure, StartFailure, WaitFailure, StopFailure, DisposeFailure;
        public List<byte[]> Submissions { get; } = [];
        public int IsExactFormatSupported(ExactPcmFormat format) { Format = format; return SupportResult; }
        public int Initialize(ExactPcmFormat format, long period100Nanoseconds) { InitializeCalls++; Format = format; Period = period100Nanoseconds; return InitializeResult; }
        public uint GetBufferFrames() => Frames;
        public int GetStreamLatency(out long latency100Nanoseconds) { latency100Nanoseconds = Latency; return LatencyResult; }
        public void Prepare() { PrepareCalls++; if (PrepareFailure is not null) throw PrepareFailure; }
        public void Submit(byte[] bytes, int offset, int count, uint frames)
        {
            Check(frames > 0 && frames <= Frames - Queued, "Fake native packet exceeds available capacity.");
            if (SubmitFailure is not null) throw SubmitFailure;
            Submissions.Add(bytes.AsSpan(offset, count).ToArray()); PacketFrames.Add(frames); Queued += frames;
        }
        public void Start() { StartCalls++; if (StartFailure is not null) throw StartFailure; }
        public uint GetQueuedFrames() { PaddingAction?.Invoke(); return Queued; }
        public int GetClockPosition(out ulong position, out ulong frequency)
        {
            ClockAction?.Invoke();
            ClockCalls++;
            var sample = ClockReads.Count > 0 ? ClockReads.Dequeue() : (Result: 0, Position, Frequency);
            position = sample.Position; frequency = sample.Frequency; return sample.Result;
        }
        public void WaitForProgress(TimeSpan delay, CancellationToken cancellationToken)
        {
            WaitCalls++; if (WaitFailure is not null) throw WaitFailure;
            if (WaitAction is not null) WaitAction(delay, cancellationToken);
            else { Position += Queued; Queued = 0; }
        }
        public void Stop() { StopCalls++; if (StopFailure is not null) throw StopFailure; ExclusivePcmOutput.RequireStopped(StopResult); }
        public void Dispose() { DisposeCalls++; DisposeAction?.Invoke(); if (DisposeFailure is not null) throw DisposeFailure; }
    }

    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void Equal<T>(T expected, T actual) { Check(EqualityComparer<T>.Default.Equals(expected, actual), $"Expected {expected}, got {actual}."); }
    private static T Throws<T>(Action action) where T : Exception
    {
        try { action(); } catch (T error) { return error; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
