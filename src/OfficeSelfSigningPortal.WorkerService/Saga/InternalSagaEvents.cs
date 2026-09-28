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
/// RueckfrageAusstehend → ReviewAusstehend ("Einreicher-Antwort eingegangen", Anhang B).
/// Verdrahtung mit der WebUI (Review-API) erfolgt in Ticket 07.
/// </summary>
public sealed record EinreicherAntwortEingegangen(
    Guid JobId,
    string Antwort,
    string SubmittedBy,
    DateTimeOffset BeantwortetAm);
