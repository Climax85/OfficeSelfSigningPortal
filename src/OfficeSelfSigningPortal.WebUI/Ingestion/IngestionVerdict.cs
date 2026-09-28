namespace OfficeSelfSigningPortal.WebUI.Ingestion;

/// <summary>Ergebnis der Ingestions-Prüfung (REQ-10, REQ-23).</summary>
public abstract record IngestionVerdict
{
    /// <summary>Upload-Regel verletzt: Ablehnung mit Grund, kein Vorgang, kein Scan.</summary>
    public sealed record Rejected(string ReasonCode, string Reason) : IngestionVerdict;

    /// <summary>Korrupte OLE/OOXML-Datei: Vorgang wird mit Status Fehler persistiert (AK-35).</summary>
    public sealed record Corrupt(string TechnicalReason) : IngestionVerdict;

    /// <summary>Makrofreie Datei: Vorgang wird mit Status NichtSignierbar persistiert (AK-36).</summary>
    public sealed record MacroFree : IngestionVerdict;

    /// <summary>Gültiger Upload: Analyseauftrag wird mit Status Eingereicht persistiert.</summary>
    public sealed record Accepted(string ContentType, string ContentSha256) : IngestionVerdict;
}
