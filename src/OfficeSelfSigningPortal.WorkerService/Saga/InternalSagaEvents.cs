using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// Interne Saga-Ereignisse (WorkerService-intern, kein Anhang-A-Vertrag — sie
/// überqueren keine Service-Grenze; Publikation erfolgt ausschließlich über den Bus
/// an die eigene Saga). Sie vervollständigen die Anhang-B-Zustandstabelle dort, wo
/// der Auslöser v1 im eigenen Service liegt und Anhang A bewusst keine Nachricht führt.
/// </summary>

/// <summary>
/// InValidierung → ScanLaeuft ("Format/Größe/Struktur ok", Anhang B).
/// Die Ingestion (Ticket 03) validiert vor der Persistierung; die Saga publiziert
/// das Ereignis nach der Aufnahme selbst (Outbox) und landet damit in ScanLaeuft.
/// </summary>
public sealed record ValidierungAbgeschlossen(Guid JobId);

/// <summary>InValidierung → NichtSignierbar ("Datei makrofrei", Anhang B).</summary>
public sealed record MakrofreieDateiErkannt(Guid JobId);

/// <summary>
/// Auslöser für die E-Mail-Benachrichtigung (Ticket 10, REQ-08): Eintritt in einen
/// Endzustand oder eine Rückfrage. WorkerService-intern (kein Anhang-A-Vertrag) —
/// der Versand transportiert ausschließlich Status + Portal-Link, niemals Inhalte,
/// Anhänge oder Befunddetails (TM-02/TM-11). <paramref name="SubmitterEmail"/> null
/// bedeutet: IdP lieferte keine Adresse — dann bleibt der Einreicher-Versand aus.
/// </summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="Zustand">Erreichten Zustand (Anhang-B-Name aus <see cref="SagaStateNames"/>).</param>
/// <param name="SubmitterEmail">E-Mail-Adresse des Einreichers (persistierter Vorgangskontext).</param>
/// <param name="SecurityTeam">Zusätzlich an das Security-Team melden (ausschließlich Malicious-Pfad, REQ-13).</param>
public sealed record BenachrichtigungAusgeloest(
    Guid JobId,
    string Zustand,
    string? SubmitterEmail,
    bool SecurityTeam);

// Hinweis: Das dritte interne Ereignis (EinreicherAntwortEingegangen) quert seit
// Ticket 07 die Service-Grenze WebUI → Saga und wurde deshalb als Vertragsnachricht
// nach Ossp.Contracts verschoben (begründete Anhang-A-Abweichung, siehe dort).
