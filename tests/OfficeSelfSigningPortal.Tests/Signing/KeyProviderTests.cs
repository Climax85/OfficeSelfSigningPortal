using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.SigningService.Keys;
using Ossp.Contracts;
using Polly.CircuitBreaker;

namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// Key-Provider (AK-53, AK-54, TC-35): LocalDev liefert ausschließlich Memory-only-Zertifikate
/// mit privatem Key; außerhalb des Dev-Profils verweigert die Registrierung den Start mit
/// eindeutiger Fehlermeldung (fail-fast). CyberArk Conjur: Erfolgspfad, fachliche
/// Authentifizierungsfehler ohne Retry, transienter Ausfall mit Retry + Circuit Breaker
/// (TC-34, AK-55).
/// </summary>
public sealed class KeyProviderTests
{
    [Fact]
    public async Task LocalDevKeyProvider_liefert_frisches_memory_only_Zertifikat_mit_privatem_Key()
    {
        // Arrange
        var provider = new LocalDevKeyProvider();

        // Act
        using var first = await provider.GetSigningCertificateAsync(CancellationToken.None);
        using var second = await provider.GetSigningCertificateAsync(CancellationToken.None);

        // Assert
        Assert.True(first.HasPrivateKey);
        Assert.NotEqual(first.Thumbprint, second.Thumbprint); // je Aufruf frisch (kurzlebig)
        var eku = first.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        Assert.NotNull(eku);
        Assert.Contains(eku!.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>(), oid => oid.Value == "1.3.6.1.5.5.7.3.3");
    }

    [Fact]
    public void AddCodeSigningKeyProvider_LocalDev_ausserhalb_Dev_Profil_start_verweigert()
    {
        // Arrange: baseline-Profil + LocalDev-Provider
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Deployment:Profile"] = "baseline",
                ["Signing:KeyProvider:Provider"] = "LocalDev",
            })
            .Build();
        var services = new ServiceCollection();

        // Act
        var exception = Assert.Throws<InvalidOperationException>(
            () => services.AddCodeSigningKeyProvider(configuration));

        // Assert: eindeutige Fehlermeldung (TC-35)
        Assert.Contains("Dev-Profil", exception.Message);
        Assert.Contains("CyberArkConjur", exception.Message);
    }

    [Fact]
    public void AddCodeSigningKeyProvider_LocalDev_im_Dev_Profil_wird_registriert()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Deployment:Profile"] = "dev",
                ["Signing:KeyProvider:Provider"] = "LocalDev",
            })
            .Build();
        var services = new ServiceCollection();

        // Act
        services.AddCodeSigningKeyProvider(configuration);
        var provider = services.BuildServiceProvider().GetService<Ossp.Contracts.ICodeSigningKeyProvider>();

        // Assert
        Assert.IsType<LocalDevKeyProvider>(provider);
    }

    [Fact]
    public async Task ConjurKeyProvider_liefert_EphemeralKeySet_Zertifikat_aus_Secrets()
    {
        // Arrange
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=OSSP Conjur Test", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        using var expected = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var p12 = expected.Export(X509ContentType.Pfx, "s3cret");
        using var http = new FakeConjurHandler((method, url) =>
            url.Contains("/authn/", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1, 2, 3, 4 }) }
                : url.EndsWith("/variable/ossp/cert", StringComparison.Ordinal)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(p12) }
                    : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("s3cret") });
        var provider = CreateProvider(http);

        // Act
        using var certificate = await provider.GetSigningCertificateAsync(CancellationToken.None);

        // Assert
        Assert.True(certificate.HasPrivateKey);
        Assert.Equal(expected.Thumbprint, certificate.Thumbprint);
    }

    [Fact]
    public async Task ConjurKeyProvider_Authentifizierung_abgelehnt_wird_nicht_retried()
    {
        // Arrange: 401 auf der Authentifizierung — fachlicher Fehler, kein Retry (Anschläge sparen)
        using var http = new FakeConjurHandler((_, url) =>
            url.Contains("/authn/", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("x") });
        var provider = CreateProvider(http);

        // Act
        var exception = await Assert.ThrowsAsync<ConjurVaultException>(
            () => provider.GetSigningCertificateAsync(CancellationToken.None));

        // Assert
        Assert.False(exception.IsTransient);
        Assert.Equal(1, http.RequestCount);
    }

    [Fact]
    public async Task ConjurKeyProvider_Vault_Ausfall_retried_dann_Circuit_Breaker()
    {
        // Arrange: Vault dauerhaft ausfallend (500 auf allen Pfaden)
        using var http = new FakeConjurHandler((_, _) => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        using var provider = CreateProvider(http, retryAttempts: 1, minDelayMs: 1, maxDelayMs: 2, breakerThroughput: 2);

        // Act: Erstaufruf scheitert nach einem Retry (2 Versuche gesamt)
        await Assert.ThrowsAsync<HttpRequestException>(
            () => provider.GetSigningCertificateAsync(CancellationToken.None));
        Assert.Equal(2, http.RequestCount);

        // Act: Zweitaufruf fällt am offenen Circuit Breaker sofort — keine weiteren
        // Requests (TC-34: Pufferung via Redelivery, fail-fast am Breaker, kein Sturm).
        await Assert.ThrowsAsync<BrokenCircuitException>(
            () => provider.GetSigningCertificateAsync(CancellationToken.None));
        await Assert.ThrowsAsync<BrokenCircuitException>(
            () => provider.GetSigningCertificateAsync(CancellationToken.None));
        Assert.Equal(2, http.RequestCount);
    }

    [Fact]
    public void AddCodeSigningKeyProvider_CyberArkConjur_registriert_KeyProvider_ueber_IHttpClientFactory()
    {
        // Arrange: CyberArk-Conjur-Provider mit minimaler Konfiguration — die HttpClient-
        // Verdrahtung muss DI-seitig über IHttpClientFactory laufen (S6, Code-Review S6).
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Deployment:Profile"] = "baseline",
                ["Signing:KeyProvider:Provider"] = "CyberArkConjur",
                ["Signing:Conjur:BaseUrl"] = "https://conjur.example.test",
                ["Signing:Conjur:Account"] = "ossp",
                ["Signing:Conjur:Login"] = "signing-service",
                ["Signing:Conjur:ApiKey"] = "fake-api-key",
                ["Signing:Conjur:CertificateSecretPath"] = "ossp/cert",
                ["Signing:Conjur:CertificatePasswordSecretPath"] = "ossp/cert-password",
            })
            .Build();
        var services = new ServiceCollection();
        services.AddCodeSigningKeyProvider(configuration);

        // Act: BuildServiceProvider materialisiert die Factory und den Provider.
        var provider = services.BuildServiceProvider();

        // Assert: IHttpClientFactory ist im DI-Container aufgelöst (Factory wurde verdrahtet)
        // und der registrierte Provider ist der Conjur-Typ — kein manuelles `new HttpClient`
        // im Registrierungspfad mehr (S6).
        Assert.NotNull(provider.GetService<System.Net.Http.IHttpClientFactory>());
        Assert.IsType<CyberArkConjurKeyProvider>(provider.GetRequiredService<ICodeSigningKeyProvider>());
    }

    [Fact]
    public async Task ConjurKeyProvider_holt_HttpClient_aus_IHttpClientFactory_pro_Request()
    {
        // Arrange: Tracking-Factory zählt jeden CreateClient-Aufruf und liefert einen
        // HttpClient mit dem registrierten FakeConjurHandler (S6: pro Request frisch).
        using var http = new FakeConjurHandler((method, url) =>
            url.Contains("/authn/", StringComparison.Ordinal)
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1, 2, 3, 4 }) }
                : url.EndsWith("/variable/ossp/cert", StringComparison.Ordinal)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }) }
                    : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("s3cret") });
        var factory = new TrackingHttpClientFactory(http);
        using var provider = new CyberArkConjurKeyProvider(factory, new ConjurKeyProviderOptions
        {
            BaseUrl = "https://conjur.example.test",
            Account = "ossp",
            Login = "signing-service",
            ApiKey = "fake-api-key",
            CertificateSecretPath = "ossp/cert",
            CertificatePasswordSecretPath = "ossp/cert-password",
            MaxRetryAttempts = 1,
            RetryMinDelay = TimeSpan.FromMilliseconds(1),
            RetryMaxDelay = TimeSpan.FromMilliseconds(2),
        });

        // Act
        _ = await Assert.ThrowsAnyAsync<Exception>(
            () => provider.GetSigningCertificateAsync(CancellationToken.None));

        // Assert: Factory wurde für die Requests konsultiert (mind. Authn + 2× Secret = 3+).
        Assert.True(factory.CreateClientCallCount >= 3,
            $"Erwartet >=3 CreateClient-Aufrufe, war {factory.CreateClientCallCount}.");
        // Assert: jeder erzeugte HttpClient wurde aus der Factory bezogen — wir verlassen
        // uns auf die TrackingFactory-Buchhaltung (verifiziert Handler-Übergabe ohne Reflection).
        Assert.NotEmpty(factory.CreatedClients);
    }

    private static CyberArkConjurKeyProvider CreateProvider(
        FakeConjurHandler handler, int retryAttempts = 3, int minDelayMs = 1, int maxDelayMs = 5, int breakerThroughput = 3)
        => new(new TrackingHttpClientFactory(handler), new ConjurKeyProviderOptions
        {
            BaseUrl = "https://conjur.example.test",
            Account = "ossp",
            Login = "signing-service",
            ApiKey = "fake-api-key",
            CertificateSecretPath = "ossp/cert",
            CertificatePasswordSecretPath = "ossp/cert-password",
            MaxRetryAttempts = retryAttempts,
            RetryMinDelay = TimeSpan.FromMilliseconds(minDelayMs),
            RetryMaxDelay = TimeSpan.FromMilliseconds(maxDelayMs),
            BreakerMinimumThroughput = breakerThroughput,
            BreakDuration = TimeSpan.FromMinutes(1),
        });

    private sealed class FakeConjurHandler : HttpMessageHandler
    {
        private readonly Func<HttpMethod, string, HttpResponseMessage> _responder;

        public FakeConjurHandler(Func<HttpMethod, string, HttpResponseMessage> responder) => _responder = responder;

        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            return Task.FromResult(_responder(request.Method, request.RequestUri?.ToString() ?? string.Empty));
        }
    }

    /// <summary>
    /// Aufzeichnender IHttpClientFactory-Stub für den S6-Test: zählt <c>CreateClient</c>-Aufrufe
    /// und liefert für jeden Namen einen frischen HttpClient, der denselben Handler teilt
    /// (Handler-Rotation durch das Produktiv-Framework simuliert).
    /// </summary>
    private sealed class TrackingHttpClientFactory : System.Net.Http.IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;

        public TrackingHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

        public int CreateClientCallCount { get; private set; }

        public List<HttpClient> CreatedClients { get; } = new();

        public HttpClient CreateClient(string name)
        {
            CreateClientCallCount++;
            var client = new HttpClient(_handler, disposeHandler: false);
            CreatedClients.Add(client);
            return client;
        }
    }
}
