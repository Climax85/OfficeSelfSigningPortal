namespace Ossp.Audit;

/// <summary>
/// Append-only Audit-Eintrag (REQ-18, TM-04/TM-07): jeder vorgangsrelevante
/// Vorgang wird mit Zeitstempel und Identität protokolliert; die Einträge sind
/// global über die Tabelle zu einer SHA-256-Hash-Kette verkettet
/// (<see cref="AuditHashChain"/>). Es gibt bewusst keine Update-/Delete-Pfade —
/// Manipulationen werden bei der Ketten-Prüfung beim Admin-Abruf erkannt
/// (AK-07, AK-18, TC-36/TC-37).
/// </summary>
public sealed class AuditEntry
{
    public long Id { get; set; }

    public Guid JobId { get; set; }

    public DateTimeOffset OccurredAt { get; set; }

    /// <summary>Ereignisart, z. B. <see cref="AuditCategories.Upload"/>.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Fachliche Ereignisbeschreibung (z. B. "Signiert: Signierung abgeschlossen").</summary>
    public string Ereignis { get; set; } = string.Empty;

    /// <summary>Identität des auslösenden Akteurs (IdP-Identität oder "system:...").</summary>
    public string Aktor { get; set; } = string.Empty;

    /// <summary>Optionale fachliche Evidenz (JSON, z. B. Auto-Signing-Evidenz nach TM-08).</summary>
    public string? Detail { get; set; }

    /// <summary>SHA-256 (hex, klein) des Vorgängereintrags — 64 Nullen beim ersten Tabelleneintrag.</summary>
    public string PrevHash { get; set; } = string.Empty;

    /// <summary>SHA-256 (hex, klein) über die kanonisierten Felder inkl. <see cref="PrevHash"/>.</summary>
    public string EntryHash { get; set; } = string.Empty;
}

/// <summary>Verbindliche Ereignisarten der Konsolidierung (Uploads, Saga-Übergänge, Guard-Ablehnungen, Reviews, Signierung).</summary>
public static class AuditCategories
{
    public const string Upload = "upload";
    public const string Saga = "saga";
    public const string Guard = "guard";
    public const string Review = "review";

    /// <summary>Signier-Evidenz (Ticket 08, REQ-18/TM-08) — ausschließlich Metadaten, kein Inhalt.</summary>
    public const string Signing = "signing";

    /// <summary>Retention-Löschung von Blob-Daten (Ticket 11, REQ-18/REQ-19) — Metadaten bleiben bestehen.</summary>
    public const string Deletion = "deletion";
}
