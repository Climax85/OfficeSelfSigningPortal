using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// ClamAV-Stage gegen einen Fake-clamd (TcpListener im Testprozess): INSTREAM-Chunking,
/// Fund-Antwort ("stream: … FOUND") vs. "stream: OK", unerreichbarer Host → Failed,
/// nicht konfiguriert → Absent.
/// </summary>
public sealed class ClamAvScanEngineTests : IAsyncLifetime
{
    private TcpListener _listener = null!;
    private int _port;
    private string _reply = "stream: OK";

    public async Task InitializeAsync()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = Task.Run(AcceptAndReplyAsync);
        await Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _listener.Stop();
        return Task.CompletedTask;
    }

    private ClamAvScanEngine CreateEngine(string? host = "127.0.0.1") =>
        new(Options.Create(new ScanEnginesOptions { ClamAvHost = host, ClamAvPort = _port }));

    private static ScanTarget Target(byte[] content) => new(content, "test.xlsm", "xlsm");

    [Fact]
    public async Task Scan_CleanReply_liefertOkOhneFunde()
    {
        // Arrange
        _reply = "stream: OK";
        var engine = CreateEngine();

        // Act
        var run = await engine.ScanAsync(Target(new byte[10]), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        Assert.Empty(run.Findings);
    }

    [Fact]
    public async Task Scan_FundReply_liefertAvFinding()
    {
        // Arrange (AK-44): Fund führt unabhängig vom Punktstand zu Malicious (Policy-Verdichtung).
        _reply = "stream: Win.Trojan.Test FOUND";
        var engine = CreateEngine();

        // Act
        var run = await engine.ScanAsync(Target(new byte[10]), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        var finding = Assert.Single(run.Findings);
        Assert.Equal(FindingCategories.Av, finding.Category);
        Assert.Equal("clamav-Win.Trojan.Test", finding.RuleId);
        Assert.Equal("Win.Trojan.Test", finding.Detail);
    }

    [Fact]
    public async Task Scan_UnerreichbarerHost_liefertFailed()
    {
        // Arrange: Port eines gestoppten Listeners — sicher geschlossen, ohne Überlauf des Portbereichs.
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var closedPort = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        var engine = new ClamAvScanEngine(Options.Create(new ScanEnginesOptions
        {
            ClamAvHost = "127.0.0.1",
            ClamAvPort = closedPort,
        }));

        // Act
        var run = await engine.ScanAsync(Target(new byte[1]), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Failed, run.State);
    }

    [Fact]
    public async Task Scan_NichtKonfiguriert_liefertAbsent()
    {
        // Arrange: kein Host konfiguriert → Stage nicht deployt.
        var engine = CreateEngine(host: null);

        // Act
        var run = await engine.ScanAsync(Target(new byte[1]), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Absent, run.State);
    }

    private async Task AcceptAndReplyAsync()
    {
        while (true)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync();
            }
            catch (SocketException)
            {
                return; // Listener gestoppt.
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await using var stream = client.GetStream();
                    var buffer = new byte[4096];
                    var command = new byte[10];
                    await ReadExactAsync(stream, command);
                    // INSTREAM-Chunks einlesen bis 0-Längen-Terminator.
                    while (true)
                    {
                        var sizePrefix = new byte[4];
                        await ReadExactAsync(stream, sizePrefix);
                        var size = BinaryPrimitives.ReadInt32BigEndian(sizePrefix);
                        if (size == 0)
                        {
                            break;
                        }

                        var remaining = size;
                        while (remaining > 0)
                        {
                            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)));
                            if (read == 0)
                            {
                                return;
                            }

                            remaining -= read;
                        }
                    }

                    var reply = System.Text.Encoding.ASCII.GetBytes(_reply);
                    await stream.WriteAsync(reply);
                }
                catch (IOException)
                {
                    // Client weg — Test ist trotzdem vorbei.
                }
            });
        }
    }

    private static async Task ReadExactAsync(System.IO.Stream stream, Memory<byte> buffer)
    {
        var readTotal = 0;
        while (readTotal < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[readTotal..]);
            if (read == 0)
            {
                throw new IOException("Verbindung geschlossen.");
            }

            readTotal += read;
        }
    }
}
