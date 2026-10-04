using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Ossp.AmsiScanBridge;

namespace OfficeSelfSigningPortal.Tests.AmsiScanBridge;

/// <summary>
/// Seam für F5 (Ticket #39, AK-57/REQ-12/IF-10): Die AmsiScanBridge ist die
/// HTTP-Brücke zum Windows-AMSI-Provider (ADR-0004). Authentisierung erfolgt über
/// ein Shared-Secret im Header <c>X-Amsi-Bridge-Token</c> — fehlt das Token oder
/// ist es falsch, antwortet die Brücke 401 (keine Scan-Antwort, kein
/// Pre-Scan-Datenleck). Tests laufen gegen den <see cref="WebApplicationFactory{TEntryPoint}"/>
/// der Bridge mit injiziertem <see cref="FakeAmsiScanner"/>.
/// </summary>
public sealed class AmsiScanBridgeTests
{
    private const string ValidToken = "test-bridge-token-1234567890";

    [Fact]
    public async Task Scan_OhneToken_antwortet401()
    {
        // Arrange
        await using var factory = new BridgeFactory(ValidToken);
        using var client = factory.CreateClient();

        // Act
        using var content = new ByteArrayContent(new byte[] { 1, 2, 3 });
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var response = await client.PostAsync("/scan", content);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Scan_FalschesToken_antwortet401()
    {
        // Arrange
        await using var factory = new BridgeFactory(ValidToken);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(AmsiScanBridgeEndpoints.TokenHeader, "wrong-token");

        // Act
        using var content = new ByteArrayContent(new byte[] { 1, 2, 3 });
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var response = await client.PostAsync("/scan", content);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Scan_MitToken_undCleanAmsi_antwortetAmsiResult0()
    {
        // Arrange
        await using var factory = new BridgeFactory(ValidToken, new FakeAmsiScanner(AmsiDetection.Clean));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(AmsiScanBridgeEndpoints.TokenHeader, ValidToken);

        // Act
        using var content = new ByteArrayContent(new byte[] { 1, 2, 3 });
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Headers.TryAddWithoutValidation(AmsiScanBridgeEndpoints.ContentNameHeader, "test.xlsm");
        using var response = await client.PostAsync("/scan", content);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("AMSI_RESULT:0", body);
    }

    [Fact]
    public async Task Scan_MitToken_undDetection_antwortetAmsiResult1MitName()
    {
        // Arrange
        await using var factory = new BridgeFactory(
            ValidToken, new FakeAmsiScanner(new AmsiDetection(IsMalicious: true, Name: "Win.Test.Signature")));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(AmsiScanBridgeEndpoints.TokenHeader, ValidToken);

        // Act
        using var content = new ByteArrayContent(new byte[] { 1, 2, 3 });
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Headers.TryAddWithoutValidation(AmsiScanBridgeEndpoints.ContentNameHeader, "test.xlsm");
        using var response = await client.PostAsync("/scan", content);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("AMSI_RESULT:1:Win.Test.Signature", body);
    }

    [Fact]
    public async Task Scan_ContentNameWirdAusHeaderAnDenScannerWeitergereicht()
    {
        // Arrange — der Brücken-Vertrag reicht X-Content-Name 1:1 an AMSI weiter,
        // damit Endpoint-AV-Signaturen mit Dateinamen statt Hash arbeiten.
        var scanner = new RecordingAmsiScanner(AmsiDetection.Clean);
        await using var factory = new BridgeFactory(ValidToken, scanner);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(AmsiScanBridgeEndpoints.TokenHeader, ValidToken);
        client.DefaultRequestHeaders.Add(AmsiScanBridgeEndpoints.ContentNameHeader, "evil.xlsm");

        // Act
        using var content = new ByteArrayContent(new byte[] { 9, 8, 7 });
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var response = await client.PostAsync("/scan", content);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(scanner.LastCalls);
        Assert.Equal("evil.xlsm", scanner.LastCalls[0].ContentName);
    }

    [Fact]
    public async Task Health_OhneAuth_antwortet200()
    {
        // Arrange — Smoke-Check-Pfad: /health ist explizit token-frei,
        // weil es als Liveness-Probe gedacht ist (keine AMSI-Daten).
        await using var factory = new BridgeFactory(ValidToken);
        using var client = factory.CreateClient();

        // Act
        using var response = await client.GetAsync("/health");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal("ok", body);
    }

    [Fact]
    public async Task Start_OhneToken_KonfigurationWirftBeiStart()
    {
        // Arrange — fehlendes Token ist fail-fast (CONVENTIONS §5: Validierung am
        // Systemrand), damit niemand versehentlich eine offene Brücke startet.
        await using var factory = new BridgeFactory(token: null);

        // Act + Assert — der WebApplicationFactory löst die Konfiguration beim
        // ersten CreateClient() auf; ohne Token verweigert die Bridge den Start.
        var exception = await Record.ExceptionAsync(() =>
        {
            using var client = factory.CreateClient();
            using var response = client.GetAsync("/health");
            return Task.CompletedTask;
        });

        Assert.NotNull(exception);
    }

    /// <summary>
    /// Test-Wrapper um den Bridge-Host: setzt das Token, ersetzt den AMSI-Scanner
    /// durch einen Fake und exponiert die Bridge als <see cref="HttpClient"/>.
    /// </summary>
    private sealed class BridgeFactory : WebApplicationFactory<Ossp.AmsiScanBridge.Program>
    {
        private readonly string? _token;
        private readonly IAmsiScanner _scanner;

        public BridgeFactory(string? token, IAmsiScanner? scanner = null)
        {
            _token = token;
            _scanner = scanner ?? new FakeAmsiScanner(AmsiDetection.Clean);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, config) =>
            {
                var dict = new Dictionary<string, string?>();
                if (_token is not null)
                {
                    dict[AmsiScanBridgeOptions.TokenConfigKey] = _token;
                }

                config.AddInMemoryCollection(dict);
            });
            builder.ConfigureTestServices(services =>
            {
                // Produktiven AMSI-Scanner durch den Fake ersetzen — der Fake ist
                // plattformneutral und für Tests verbindlich.
                services.RemoveAll(typeof(IAmsiScanner));
                services.AddSingleton(_scanner);
            });
        }
    }
}