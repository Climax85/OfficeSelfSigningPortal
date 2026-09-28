using System.Net;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Scanning;
using OfficeSelfSigningPortal.WorkerService.Scanning.Vba;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Scanning;

/// <summary>
/// AMSI-Stage gegen Fake-HttpMessageHandler: Detection-Antwort, Clean, Bridge-Fehler
/// (→ Failed → Inconclusive-Policy) und nicht konfiguriert (→ Absent, AK-46).
/// </summary>
public sealed class AmsiScanEngineTests
{
    private const string BridgeUrl = "http://bridge.test/scan";

    private static AmsiScanEngine CreateEngine(HttpResponseMessage response, bool enabled = true)
    {
        var handler = new StubHandler(response);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://bridge.test") };
        var engines = new ScanEnginesOptions { AmsiEnabled = enabled, AmsiBridgeUrl = BridgeUrl };
        return new AmsiScanEngine(httpClient, Options.Create(engines));
    }

    private static ScanTarget Target() => new([1, 2, 3], "test.xlsm", "xlsm");

    [Fact]
    public async Task Scan_Detection_liefertAvFinding()
    {
        // Arrange
        var engine = CreateEngine(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("AMSI_RESULT:1:Win.Test.Detection"),
        });

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        var finding = Assert.Single(run.Findings);
        Assert.Equal(FindingSources.Amsi, finding.Source);
        Assert.Equal("Win.Test.Detection", finding.Detail);
    }

    [Fact]
    public async Task Scan_Clean_liefertOkOhneFunde()
    {
        // Arrange
        var engine = CreateEngine(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("AMSI_RESULT:0"),
        });

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        Assert.Empty(run.Findings);
    }

    [Fact]
    public async Task Scan_BridgeFehler_liefertFailed()
    {
        // Arrange: HTTP 500 — für die Policy ein AMSI-Ausfall (Inconclusive, TC-19).
        var engine = CreateEngine(new HttpResponseMessage(HttpStatusCode.InternalServerError));

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Failed, run.State);
    }

    [Fact]
    public async Task Scan_BridgeUnErreichbar_liefertFailed()
    {
        // Arrange
        var httpClient = new HttpClient(new ThrowingHandler());
        var engines = new ScanEnginesOptions { AmsiEnabled = true, AmsiBridgeUrl = BridgeUrl };
        var engine = new AmsiScanEngine(httpClient, Options.Create(engines));

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Failed, run.State);
    }

    [Fact]
    public async Task Scan_NichtAktiviert_liefertAbsent()
    {
        // Arrange (AK-46): Profil baseline registriert die Stage nicht — Absent ist der Vertrag.
        var engine = CreateEngine(new HttpResponseMessage(HttpStatusCode.OK), enabled: false);

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Absent, run.State);
    }

    private sealed class StubHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response);
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("Verbindung fehlgeschlagen.");
    }
}
