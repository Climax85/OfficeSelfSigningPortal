namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Lesender Zugriff des WorkerService auf den Artefakt-Blob-Speicher der Ingestion
/// (Portal-DB, T03). Der Blob-Transport über den Bus ist ausgeschlossen (25-MB-Payloads);
/// die Saga führt nur die Vertrags-Metadaten (Anhang A). Null-Rückgabe = Blob fehlt
/// (der Consumer reagiert mit Retry → DLQ → JobFailed, TC-16).
/// </summary>
public interface IArtifactBlobStore
{
    Task<ArtifactBlob?> ReadAsync(Guid artifactId, CancellationToken cancellationToken);
}

/// <param name="Content">Datei-Bytes.</param>
/// <param name="ContentSha256">Hex-SHA-256 des Blobs (TOCTOU-Basis, TM-03).</param>
public sealed record ArtifactBlob(byte[] Content, string ContentSha256);
