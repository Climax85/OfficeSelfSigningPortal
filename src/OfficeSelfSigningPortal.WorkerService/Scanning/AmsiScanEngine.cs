using System.Net.Http.Headers;
using System.Net.Mime;
using Microsoft.Extensions.Options;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Optionale AMSI-Stage (Profil <c>hardened</c>, ADR-0004, REQ-12): reicht den Datei-Stream
/// an die AmsiScanBridge (Windows-Host außerhalb Aspire) und verdichtet das AMSI-Ergebnis.
/// Ausfall/Timeout der Bridge ist kein Score-Signal, sondern führt zwingend zu
/// <see cref="Verdict.Inconclusive"/> (Review-Pflicht, kein Auto-Signing — TC-19, AK-26).
///
/// Bridge-Vertrag (wird mit dem Bridge-Bau, ADR-0004, final verdrahtet): POST des
/// Datei-Bytes mit X-Content-Name; Antwort "AMSI_RESULT:int" (0 = Clean, 1 = Detected,
/// ggf. Detection-Name nach Doppelpunkt). Nicht erreichbar/Timeout → EngineResult Failed.
/// Im Profil <c>baseline</c> wird diese Stage nicht registriert — der Orchestrator
/// meldet AMSI dann als <see cref="EngineState.Absent"/> (AK-46).
/// </summary>
public sealed class AmsiScanEngine(
    HttpClient httpClient,
    IOptions<ScanEnginesOptions> options) : IScanEngine
{
    public const string ContentNameHeader = "X-Content-Name";

    public string EngineName => FindingSources.Amsi;

    public async Task<EngineRun> ScanAsync(ScanTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var config = options.Value;

        if (!config.AmsiEnabled || string.IsNullOrWhiteSpace(config.AmsiBridgeUrl))
        {
            return new EngineRun(EngineName, EngineState.Absent, "AMSI-Bridge nicht konfiguriert", []);
        }

        try
        {
            using var content = new ByteArrayContent(target.Content);
            content.Headers.ContentType = new MediaTypeHeaderValue(MediaTypeNames.Application.Octet);
            content.Headers.TryAddWithoutValidation(ContentNameHeader, target.OriginalFileName);

            using var response = await httpClient.PostAsync(config.AmsiBridgeUrl, content, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new EngineRun(EngineName, EngineState.Failed, $"Bridge-HTTP {(int)response.StatusCode}", []);
            }

            var body = (await response.Content.ReadAsStringAsync(cancellationToken)).Trim();
            return ParseBridgeResult(body);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            // TaskCanceledException schließt den HttpClient-eigenen Timeout mit ein —
            // beides ist für die Policy ein AMSI-Ausfall (Inconclusive, TC-19).
            return new EngineRun(EngineName, EngineState.Failed, ex.GetType().Name, []);
        }
    }

    private EngineRun ParseBridgeResult(string body)
    {
        // "AMSI_RESULT:0" = Clean, "AMSI_RESULT:1:Signature.Name" = Detected.
        if (!body.StartsWith("AMSI_RESULT:", StringComparison.Ordinal))
        {
            return new EngineRun(EngineName, EngineState.Degraded, $"Unerwartete Bridge-Antwort: {body}", []);
        }

        var result = body["AMSI_RESULT:".Length..];
        if (result.StartsWith("1", StringComparison.Ordinal))
        {
            var detection = result.Length > 2 ? result[2..] : "AMSI-Detection";
            return new EngineRun(
                EngineName,
                EngineState.Ok,
                null,
                [new ScanFinding(
                    Source: FindingSources.Amsi,
                    Category: FindingCategories.Av,
                    RuleId: "amsi-detection",
                    Points: 0,
                    Detail: detection)]);
        }

        if (result.StartsWith("0", StringComparison.Ordinal))
        {
            return new EngineRun(EngineName, EngineState.Ok, null, []);
        }

        return new EngineRun(EngineName, EngineState.Degraded, $"Nicht unterstütztes AMSI_RESULT: {result}", []);
    }
}
