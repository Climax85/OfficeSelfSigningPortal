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

    [Fact]
    public async Task Scan_BridgeUnauthorized_liefertFailed()
    {
        // Arrange (F5/SF-04): Brücke antwortet 401 (Token fehlt/falsch). Für die
        // Verdict-Policy ist das ein AMSI-Ausfall (Inconclusive → Review-Pflicht).
        var engine = CreateEngine(new HttpResponseMessage(HttpStatusCode.Unauthorized));

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Failed, run.State);
        Assert.Contains("401", run.Detail);
    }

    [Fact]
    public async Task Scan_MitTokenFuegtHeaderHinzu()
    {
        // Arrange (F5/SF-04): der WorkerService sendet das konfigurierte Shared-Secret
        // als X-Amsi-Bridge-Token — sonst antwortet die Brücke 401 (siehe voriger Test).
        var handler = new CapturingHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("AMSI_RESULT:0"),
            });
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://bridge.test") };
        var engines = new ScanEnginesOptions
        {
            AmsiEnabled = true,
            AmsiBridgeUrl = BridgeUrl,
            AmsiBridgeToken = "shared-secret-xyz",
        };
        var engine = new AmsiScanEngine(httpClient, Options.Create(engines));

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Ok, run.State);
        Assert.NotNull(handler.LastRequest);
        Assert.True(
            handler.LastRequest!.Headers.TryGetValues("X-Amsi-Bridge-Token", out var values),
            "X-Amsi-Bridge-Token-Header wurde nicht gesetzt.");
        Assert.Equal("shared-secret-xyz", values!.Single());
    }

    [Fact]
    public async Task Scan_OhneTokenKonfiguriert_sendetKeinenHeader()
    {
        // Arrange — Token bleibt leer (Default-Verhalten), der Worker sendet keinen
        // Header. Die Brücke antwortet dann 401, was die Engine als Failed
        // verdichtet (Smoke-Check im Profil hardened ohne Token-Konfiguration).
        var handler = new CapturingHandler(
            new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("http://bridge.test") };
        var engines = new ScanEnginesOptions
        {
            AmsiEnabled = true,
            AmsiBridgeUrl = BridgeUrl,
            AmsiBridgeToken = null,
        };
        var engine = new AmsiScanEngine(httpClient, Options.Create(engines));

        // Act
        var run = await engine.ScanAsync(Target(), CancellationToken.None);

        // Assert
        Assert.Equal(EngineState.Failed, run.State);
        Assert.False(handler.LastRequest!.Headers.Contains("X-Amsi-Bridge-Token"));
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

    private sealed class CapturingHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(response);
        }
    }
}
