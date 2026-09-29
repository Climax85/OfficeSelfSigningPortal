namespace OfficeSelfSigningPortal.Tests.Signing;

/// <summary>
/// Golden-File-Verifikation (AK-51, TC-33 b): Office-signierte Fixtures für .xlsm/.docm/.pptm
/// werden gegen den eigenen VbaProjectSigner laufen gelassen — Byte-für-Byte-Digest-Vergleich
/// der Normalisierung gegen den in der Office-Signatur eingebetteten Digest plus
/// Verifizierung gegen den MS-OVBA-Contents-Hash.
///
/// MANUELLER VORLAUF (Ticket 08): Die Fixtures werden mit Office/signtool auf Windows erzeugt
/// (examples/golden/README.md) und liegen noch nicht vor — der Test ist bis dahin übersprungen.
/// Die Normalisierung selbst ist unabhängig gegen die Python-Referenzimplementation
/// (tools/reference/v3hash_reference.py) byte-für-byte validiert (VbaContentHasherTests);
/// die Roundtrip-Verifizierung (Signieren → CMS-Prüfung → Contents-Hash-Bindung) läuft
/// produktiv in VbaProjectSignerTests.
/// </summary>
public sealed class GoldenFileSigningTests
{
    [Fact(Skip = "Manueller Vorlauf: Office-signierte Golden Files fehlen noch (examples/golden/README.md)")]
    public Task Office_signierte_Fixtures_digest_Vergleich_und_contents_hash_verifikation()
    {
        // Act (folgt mit den Fixtures — siehe README im Ordner examples/golden):
        // 1. Aus vbaProjectSignatureV3.bin der Fixture CMS-DER extrahieren (DigSigInfoSerialized).
        // 2. SignedCms.Decode + CheckSignature.
        // 3. Bindungs-Digest (SigDataV1Serialized.sourceHash) mit
        //    VbaContentHasher.ComputeV3ContentHash(vbaProject.bin) byte-für-byte vergleichen.
        // 4. VbaProjectSigner signiert das Dokument erneut → Schritt 1–3 wiederholen.
        return Task.CompletedTask;
    }
}
