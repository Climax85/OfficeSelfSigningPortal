namespace Ossp.Contracts;

/// <summary>
/// Signierauftrag Saga → SigningService (Anhang A, exakter Vertrag).
/// Die Sign-Queue ist nur von der Saga erreichbar (REQ-14, TM-19); der SigningService
/// verifiziert <see cref="ContentSha256"/> und den Saga-Status vor jeder Signatur.
/// </summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="ArtifactId">Referenz auf persistierten Datei-Blob.</param>
/// <param name="ContentSha256">muss zum gescannten Blob passen — Verifizierung vor Signatur (TOCTOU, TM-03/TM-19).</param>
/// <param name="OriginalFileName">Originalname der Datei.</param>
/// <param name="ContentType">"xlsm" | "docm" | "pptm".</param>
/// <param name="RequestedBy">bei Auto-Signing: "system:auto-sign"; bei Review-Freigabe: Bearbeiter-ID.</param>
/// <param name="RequestedAt">Zeitstempel (UTC).</param>
public sealed record SignMacroRequested(
    Guid JobId,
    Guid ArtifactId,
    string ContentSha256,
    string OriginalFileName,
    string ContentType,
    string RequestedBy,
    DateTimeOffset RequestedAt);

/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="SignedArtifactId">neue Blob-Referenz auf signierte Datei.</param>
/// <param name="SignedAt">Zeitstempel (UTC).</param>
public sealed record SignMacroCompleted(
    Guid JobId,
    Guid SignedArtifactId,
    DateTimeOffset SignedAt);

/// <summary>
/// <paramref name="Retryable"/> = false bei Signatur-Validierungsfehler
/// (VbaProjectSigner/Golden-File-Abweichung, TC-29).
/// </summary>
/// <param name="JobId">Vorgangs-ID.</param>
/// <param name="Reason">fachlicher Grund (keine Exception-Texte).</param>
/// <param name="Retryable">false ⇒ kein erneuter Versuch, Vorgang → <c>Fehler</c>.</param>
public sealed record SignMacroFailed(
    Guid JobId,
    string Reason,
    bool Retryable);
