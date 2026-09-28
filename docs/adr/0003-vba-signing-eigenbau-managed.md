# VBA-Signierung: Eigenbau `VbaProjectSigner` (managed .NET), Windows-SIP-Agent als dokumentierter Fallback

Datum: 2025-09-27

Die VBA-Projekt-Signatur wird als eigenständiger, rein managed .NET-Baustein (`VbaProjectSigner`, hinter `IVbaProjectSigner`) implementiert: MS-OVBA-§2.4.2-Normalisierung (V3: `V3ContentNormalizedData || ProjectNormalizedData`, SHA-256), CMS/PKCS#7 via `SignedCms`, CFB-Rewriting via OpenMcdf — einheitlich für .xlsm/.docm/.pptm, lauffähig im Linux-Container, null Lizenzkosten. Begründung: Alle kommerziellen .NET-Libraries (EPPlus, Aspose, GroupDocs) sind Excel-only und lizenzpflichtig; OSS-Libraries, die VBA-Signaturen erzeugen, existieren in keiner Sprache. Die Microsoft-Referenz-Implementierung (signtool + Office-SIPs) ist kostenlos, aber x86-only, Windows-only und benötigt Disk-Materialisierung der Datei — sie widerspräche der Container-Isolation des SigningService. Sie bleibt als Fallback dokumentiert: Scheitert die Normalisierung am Golden-File-Test, wird hinter `IVbaProjectSigner` auf den Windows-Agenten umgeschwenkt (kein Contract-Bruch).

Considered Options: EPPlus/Aspose/GroupDocs (Excel-only, Lizenzkosten), Set-AuthenticodeSignature/Office-SIPs als Primärweg (Windows-x86, Disk-Footprint), Office-Interop (Desktop-Office nötig, serverseitig nicht supportet).
