namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Konfiguration der Engine-Stages (Abschnitt <see cref="SectionName"/>): Stage-Timeouts
/// mit CancellationToken (TM-15), ClamAV-Endpunkt, YARA-Regelwerk-Pfad und die optionale
/// AMSI-Bridge (Profil <c>hardened</c>, ADR-0004). Nichts davon ist secret — der
/// Abschnitt darf in <c>appsettings.json</c> unter Versionskontrolle stehen.
/// </summary>
public sealed class ScanEnginesOptions
{
    public const string SectionName = "Scanning:Engines";

    /// <summary>Timeout der Heuristik-Stage (OpenMcdf + Keyword-Analyse).</summary>
    public TimeSpan HeuristicsStageTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Timeout der YARA-Stage (native libyara hat kein eigenes Cancel — app-seitige Deadline).</summary>
    public TimeSpan YaraStageTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Timeout der ClamAV-Stage (clamd-INSTREAM).</summary>
    public TimeSpan ClamAvStageTimeout { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Timeout der AMSI-Bridge (synchrone Windows-AMSI-Abfrage → app-seitige Deadline, R1/TM-15).</summary>
    public TimeSpan AmsiStageTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>clamd-Host (leer = Stage nicht deployt → <see cref="Ossp.Contracts.EngineState.Absent"/>).</summary>
    public string? ClamAvHost { get; set; }

    public int ClamAvPort { get; set; } = 3310;

    /// <summary>Pfad der kuratierten YARA-Regeln (Container-Image/Content, TM-05).</summary>
    public string YaraRulesPath { get; set; } = "rules/ossp-curated.yar";

    /// <summary>Profil <c>hardened</c>: AMSI-Bridge als Engine-Stage (ADR-0004). Baseline lässt die Stage weg.</summary>
    public bool AmsiEnabled { get; set; }

    /// <summary>HTTP-Endpunkt der AMSI-Bridge (nur ausgewertet, wenn <see cref="AmsiEnabled"/>).</summary>
    public string? AmsiBridgeUrl { get; set; }

    /// <summary>
    /// Shared-Secret für die AMSI-Bridge-Authentisierung (F5, SF-04). Wird im
    /// <c>AmsiScanEngine</c> als <c>X-Amsi-Bridge-Token</c>-Header gesetzt;
    /// fehlt der Wert, sendet der Worker keinen Header und die Brücke antwortet
    /// 401 (→ AMSI-Ausfall, Inconclusive-Policy, AK-26). Konfiguration ausschließlich
    /// über Aspire-Parameter/Umgebungsvariablen (REQ-24, TM-12).
    /// </summary>
    public string? AmsiBridgeToken { get; set; }
}
