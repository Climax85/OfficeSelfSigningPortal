namespace Ossp.AmsiScanBridge;

/// <summary>
/// Konfiguration der AmsiScanBridge (F5, IF-10, ADR-0004).
///
/// <para>Das <see cref="Token"/>-Shared-Secret ist die einzige Authentisierung
/// zwischen WorkerService und Bridge (Ticket #39, SF-04-Backlog): der Header
/// <see cref="AmsiScanBridgeEndpoints.TokenHeader"/> trägt den Wert im Klartext
/// (TLS-gesichert im Produktionsbetrieb), und die Bridge antwortet bei
/// fehlendem/falschem Token mit 401 ohne AMSI-Aufruf — kein Datenleck vor der
/// Authentisierung.</para>
///
/// <para>Standardpfad <see cref="ListenUrl"/> ist die Loopback-Adresse; der
/// WorkerService ruft die Bridge über denselben Host auf (REQ-12, ADR-0004).</para>
/// </summary>
public sealed class AmsiScanBridgeOptions
{
    public const string SectionName = "AmsiScanBridge";

    /// <summary>Konfigurations-Schlüssel des Shared-Secrets (für BindConfiguration).</summary>
    public const string TokenConfigKey = "AmsiScanBridge:Token";

    /// <summary>Shared-Secret zwischen WorkerService und Bridge (SF-04-Disposition F5).</summary>
    public string? Token { get; set; }

    /// <summary>
    /// Kestrel-Listen-URL. Standard: Loopback-only (REQ-12 Härtung). In
    /// Container-/Host-Setups explizit auf 0.0.0.0 setzen, wenn der WorkerService
    /// auf einem anderen Container-Host liegt — innerhalb des Aspire-AppHost
    /// übernimmt Aspire die Verdrahtung über den Service-Endpoint.
    /// </summary>
    public string ListenUrl { get; set; } = "http://127.0.0.1:5101";

    /// <summary>Maximale Anfrage-Body-Größe (Bytes). Default 26 MB = 25 MB Upload-Limit + OLE-Overhead.</summary>
    public long MaxRequestBodyBytes { get; set; } = 26L * 1024 * 1024;
}