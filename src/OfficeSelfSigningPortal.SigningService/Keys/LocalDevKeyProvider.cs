using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Keys;

/// <summary>
/// Dev-Key-Provider (AK-53, REQ-15/24): erzeugt pro Aufruf ein frisches, selbstsigniertes
/// Codesigning-Zertifikat (RSA 2048, Code-Signing-EKU) ausschließlich im Arbeitsspeicher.
/// Das Private-Key-Material wird niemals exportiert oder persisted — außerhalb des
/// Dev-Profils verweigert die Registrierung den Start (AK-54, TC-35, TM-20).
/// </summary>
public sealed class LocalDevKeyProvider : ICodeSigningKeyProvider
{
    public Task<X509Certificate2> GetSigningCertificateAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=OSSP LocalDev Signing",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.3")], // Code Signing
            critical: false));

        var created = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(7));

        // Reimport als PKCS#12 mit EphemeralKeySet: Private-Key-Material bleibt
        // memory-only und überlebt keinen Export (ADR-0002, REQ-15).
        var certificate = X509CertificateLoader.LoadPkcs12(
            created.Export(X509ContentType.Pfx),
            password: null,
            X509KeyStorageFlags.EphemeralKeySet);
        created.Dispose();

        return Task.FromResult(certificate);
    }
}
