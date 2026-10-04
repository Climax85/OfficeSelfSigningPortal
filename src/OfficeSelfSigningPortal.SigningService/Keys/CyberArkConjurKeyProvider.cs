using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Ossp.Contracts;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;

namespace OfficeSelfSigningPortal.SigningService.Keys;

/// <summary>
/// Konfiguration des CyberArk-Conjur-Key-Providers (Produktiv-Primär, AK-53/AK-55, REQ-15/22).
/// Sensible Werte (ApiKey) ausschließlich über Aspire-Parameter/Umgebungsvariablen (REQ-24).
/// </summary>
public sealed class ConjurKeyProviderOptions
{
    public const string SectionName = "Signing:Conjur";

    public required string BaseUrl { get; set; }

    public required string Account { get; set; }

    public required string Login { get; set; }

    public required string ApiKey { get; set; }

    /// <summary>Variablenpfad des PKCS#12-Secrets (Codesigning-Zertifikat inkl. Key).</summary>
    public required string CertificateSecretPath { get; set; }

    /// <summary>Variablenpfad des Passwort-Secrets für das PKCS#12.</summary>
    public required string CertificatePasswordSecretPath { get; set; }

    public int MaxRetryAttempts { get; set; } = 5;

    public TimeSpan RetryMinDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    public TimeSpan RetryMaxDelay { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Ab wie vielen Fehlern in der Stichprobe der Circuit Breaker öffnet.</summary>
    public int BreakerMinimumThroughput { get; set; } = 3;

    public TimeSpan BreakDuration { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Produktiv-Key-Provider über CyberArk Conjur (AK-55, TC-34, TM-16, REQ-15/22):
/// Authentifizierung per API-Key (Conjur /authn), dann Auslesen von PKCS#12-Bytes und
/// Passwort-Variable; das Zertifikat wird mit <c>EphemeralKeySet</c> ausschließlich im
/// Arbeitsspeicher materialisiert. Um den Vault-Pfad liegt eine Polly-Pipeline:
/// exponentieller Retry mit Jitter + Circuit Breaker — ein Vault-Ausfall schlägt schnell
/// und kontrolliert fehl, die MassTransit-Redelivery der Sign-Queue puffert die Aufträge,
/// nach Retry-Limit landen sie in der Fault-Queue (kein Request-Verlust).
///
/// HttpClient wird pro Aufruf aus <see cref="IHttpClientFactory"/> bezogen (F6/S6): keine
/// manuell konstruierten HttpClient-Instanzen mehr im DI-Pfad, DNS-Refresh und Handler-
/// Rotation folgen dem Framework.
/// </summary>
public sealed class CyberArkConjurKeyProvider : ICodeSigningKeyProvider, IDisposable
{
    /// <summary>Name des registrierten HttpClient-Namensclients (siehe <c>KeyProviderServiceCollectionExtensions</c>).</summary>
    public const string HttpClientName = "CyberArkConjurKeyProvider";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ConjurKeyProviderOptions _options;
    private readonly ResiliencePipeline _pipeline;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private string? _cachedToken;
    private DateTimeOffset _tokenValidUntil = DateTimeOffset.MinValue;

    public CyberArkConjurKeyProvider(IHttpClientFactory httpClientFactory, ConjurKeyProviderOptions options)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;

        var retryDelays = Ossp.Contracts.OsspBusConventions.JitteredExponentialIntervals(
            Math.Max(options.MaxRetryAttempts, 1),
            options.RetryMinDelay,
            options.RetryMaxDelay);

        _pipeline = new ResiliencePipelineBuilder()
            .AddRetry(new RetryStrategyOptions
            {
                MaxRetryAttempts = options.MaxRetryAttempts,
                ShouldHandle = args => ValueTask.FromResult(
                    args.Outcome.Exception is HttpRequestException
                    or BrokenCircuitException
                    or ConjurVaultException { IsTransient: true }),
                DelayGenerator = args => ValueTask.FromResult<TimeSpan?>(
                    args.AttemptNumber < retryDelays.Length
                        ? retryDelays[args.AttemptNumber]
                        : options.RetryMaxDelay),
            })
            .AddCircuitBreaker(new CircuitBreakerStrategyOptions
            {
                FailureRatio = 0.5,
                SamplingDuration = TimeSpan.FromSeconds(30),
                MinimumThroughput = Math.Max(options.BreakerMinimumThroughput, 1),
                BreakDuration = options.BreakDuration,
                ShouldHandle = args => ValueTask.FromResult(args.Outcome.Exception
                    is HttpRequestException or ConjurVaultException),
            })
            .Build();
    }

    public async Task<X509Certificate2> GetSigningCertificateAsync(CancellationToken ct)
    {
        // CircuitBreakerException (vom Polly-Breaker geworfen) läuft durch — der
        // Signing-Consumer übersetzt sie in SignMacroFailed(Retryable: true).
        var (p12, password) = await _pipeline.ExecuteAsync(
            async innerCt => (await ReadCertificateSecretAsync(innerCt), await ReadPasswordSecretAsync(innerCt)),
            ct);

        try
        {
            return X509CertificateLoader.LoadPkcs12(
                p12,
                password,
                X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new ConjurVaultException(
                "Das Conjur-Secret ist kein lesbares PKCS#12 (Zertifikat/Passwort ungültig).", ex);
        }
    }

    internal async Task<byte[]> ReadCertificateSecretAsync(CancellationToken ct)
        => await ReadSecretAsync(_options.CertificateSecretPath, ct);

    internal async Task<string> ReadPasswordSecretAsync(CancellationToken ct)
        => Encoding.UTF8.GetString(await ReadSecretAsync(_options.CertificatePasswordSecretPath, ct));

    private async Task<byte[]> ReadSecretAsync(string path, CancellationToken ct)
    {
        var token = await GetTokenAsync(ct);
        // Pro Aufruf frisch aus der Factory — DNS-Refresh, Handler-Rotation und
        // HttpClient-Lebenszyklus werden vom Framework verwaltet (F6/S6).
        using var httpClient = _httpClientFactory.CreateClient(HttpClientName);
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"{_options.BaseUrl.TrimEnd('/')}/secrets/{_options.Account}/variable/{path}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Token", $"token=\"{token}\"");

        using var response = await httpClient.SendAsync(request, ct);
        if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
        {
            throw new ConjurVaultException(
                $"Conjur-Secret '{path}' nicht gefunden oder nicht berechtigt ({(int)response.StatusCode}).");
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(ct);
    }

    private async Task<string> GetTokenAsync(CancellationToken ct)
    {
        if (_cachedToken is not null && DateTimeOffset.UtcNow < _tokenValidUntil)
        {
            return _cachedToken;
        }

        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_cachedToken is not null && DateTimeOffset.UtcNow < _tokenValidUntil)
            {
                return _cachedToken;
            }

            // Token-Pfad ebenfalls über die Factory (F6/S6).
            using var httpClient = _httpClientFactory.CreateClient(HttpClientName);
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                $"{_options.BaseUrl.TrimEnd('/')}/authn/{_options.Account}/{_options.Login}/authenticate");
            request.Content = new StringContent(_options.ApiKey, Encoding.UTF8, "text/plain");

            using var response = await httpClient.SendAsync(request, ct);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new ConjurVaultException(
                    "Conjur-Authentifizierung abgelehnt — Login/API-Key ungültig (kein Retry).");
            }

            response.EnsureSuccessStatusCode();
            var token = Convert.ToBase64String(await response.Content.ReadAsByteArrayAsync(ct));
            _cachedToken = token;
            // Conjur-Tokens laufen üblicherweise nach 8 Minuten ab — früh erneuern.
            _tokenValidUntil = DateTimeOffset.UtcNow.AddMinutes(5);
            return token;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    public void Dispose() => _tokenLock.Dispose();
}

/// <summary>
/// Fachlicher Fehler des Conjur-Pfads (stabile Klasse für Polly-Handling und Tests):
/// Authentifizierungs-/Berechtigungsfehler sind nicht transient und werden nicht retried.
/// </summary>
public sealed class ConjurVaultException : Exception
{
    public ConjurVaultException(string message, bool isTransient = false)
        : base(message)
    {
        IsTransient = isTransient;
    }

    public ConjurVaultException(string message, Exception innerException, bool isTransient = false)
        : base(message, innerException)
    {
        IsTransient = isTransient;
    }

    /// <summary>Transiente Fehler (Netz, 5xx) werden per Retry gepuffert; fachliche Fehler nicht.</summary>
    public bool IsTransient { get; }
}