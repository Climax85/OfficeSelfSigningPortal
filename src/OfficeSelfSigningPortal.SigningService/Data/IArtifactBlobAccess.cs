namespace OfficeSelfSigningPortal.SigningService.Data;

/// <summary>
/// Zugriff des SigningService auf die Artefakt-Tabelle der Portal-DB (WebUI-Migration, T03).
/// Lesend für den Signier-Input; der signierte Blob wird als neue Artefakt-Zeile abgelegt
/// (<see cref="StoreSignedAsync"/> — neue <c>SignedArtifactId</c>, Original bleibt unverändert).
/// </summary>
public interface IArtifactBlobAccess
{
    Task<ArtifactBlobContent?> ReadAsync(Guid artifactId, CancellationToken cancellationToken);

    /// <summary>Legt den signierten Blob als neue Zeile ab und liefert dessen SHA-256 (Hex, Großbuchstaben).</summary>
    Task<string> StoreSignedAsync(Guid artifactId, byte[] content, CancellationToken cancellationToken);
}

/// <param name="Content">Datei-Bytes.</param>
/// <param name="ContentSha256">persistierter SHA-256 des Blobs (TOCTOU-Basis, TM-03).</param>
public sealed record ArtifactBlobContent(byte[] Content, string ContentSha256);
