namespace OfficeSelfSigningPortal.WorkerService.Retention;

/// <summary>
/// Löschpfad der Artefakt-Tabelle für den Retention-Job (Ticket 11, REQ-19).
/// Der Scan-Pfad (<see cref="Scanning.PostgresArtifactBlobStore"/>) bleibt bewusst
/// read-only — nur der Retention-Job erhält einen Schreibpfad auf Blob-Ebene.
/// </summary>
public interface IRetentionBlobStore
{
    /// <summary>
    /// Löscht die angegebenen Artefakt-Zeilen (Original und/oder signiert) und gibt
    /// die Anzahl der tatsächlich gelöschten Zeilen zurück — 0 signalisiert, dass
    /// der Retention-Lauf für diesen Vorgang bereits abgeschlossen war (Idempotenz).
    /// </summary>
    Task<int> DeleteAsync(IReadOnlyCollection<Guid> artifactIds, CancellationToken cancellationToken);
}
