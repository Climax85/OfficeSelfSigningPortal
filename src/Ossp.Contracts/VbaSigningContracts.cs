using System.Security.Cryptography.X509Certificates;

namespace Ossp.Contracts;

/// <summary>
/// Ergebnis eines VBA-Projekt-Signiervorgangs (Anhang A, exakter Vertrag).
/// </summary>
/// <param name="Success">true ⇒ Signaturpart wurde erzeugt; false ⇒ <paramref name="ErrorCode"/> ist gesetzt.</param>
/// <param name="ErrorCode">stabiler, fachlicher Fehlercode (keine Exception-Texte).</param>
public sealed record SignResult(bool Success, string? ErrorCode);

/// <summary>
/// Signiert das VBA-Projekt eines OOXML-Dokuments (.xlsm/.docm/.pptm) gemäß Anhang C
/// (MS-OVBA-V3-Normalisierung, SHA-256, SignedCms mit SpcIndirectDataContent).
/// Implementierungen: <c>VbaProjectSigner</c> (Primär, managed, Linux) |
/// <c>WindowsSigningAgentSigner</c> (Fallback, ADR-0003). Der Signer greift nie selbst
/// auf Key-Provider zu — das Zertifikat kommt ausschließlich als Parameter
/// (Trennung via <see cref="ICodeSigningKeyProvider"/>, Anhang C Ziffer 5).
/// </summary>
public interface IVbaProjectSigner
{
    Task<SignResult> SignAsync(Stream document, X509Certificate2 certificate, CancellationToken ct);
}

/// <summary>
/// Liefert pro Aufruf ein frisches, Memory-only-Zertifikat (<c>EphemeralKeySet</c>) —
/// das Key-Material liegt maximal kurzlebig im Arbeitsspeicher (REQ-15, TM-09, ADR-0002).
/// Implementierungen: <c>LocalDevKeyProvider</c> | <c>CyberArkConjurKeyProvider</c> |
/// <c>AzureKeyVaultKeyProvider</c>. Der Aufrufer ist für das zeitnahe Disposen des
/// zurückgegebenen Zertifikats verantwortlich.
/// </summary>
public interface ICodeSigningKeyProvider
{
    Task<X509Certificate2> GetSigningCertificateAsync(CancellationToken ct);
}
