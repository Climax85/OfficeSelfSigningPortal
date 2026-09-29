# Golden Files — VBA-V3-Signatur (manueller Vorlauf, Ticket 08 / AK-51 / TC-33)

Dieser Ordner nimmt die mit **Office bzw. signtool auf Windows** erzeugten, signierten
Fixtures auf. Erst mit diesen Dateien wird der in `GoldenFileSigningTests` hinterlegte
Byte-für-Byte-Digest-Vergleich freigeschaltet (aktuell per `Skip` dokumentiert).

## Benötigte Fixtures

| Datei | Inhalt |
|---|---|
| `golden.xlsm` | Excel-Arbeitsmappe mit VBA-Projekt (mindestens ein Standardmodul), VBA-Projekt digital signiert |
| `golden.docm` | Word-Dokument mit VBA-Projekt, signiert |
| `golden.pptm` | PowerPoint-Präsentation mit VBA-Projekt, signiert |

## Erzeugung

1. Selbstsigniertes Codesigning-Zertifikat erzeugen (Windows):
   `New-SelfSignedCertificate -Type CodeSigning -CertStoreLocation Cert:\CurrentUser\My -Subject "CN=OSSP GoldenFile"`
2. Datei in Office öffnen → VBA-Editor → Extras → Digitale Signatur → Zertifikat wählen → speichern.
   (Alternativ signtool + Office-SIPs, siehe Research R2 — drei Durchläufe Legacy/Agile/V3.)
3. Dateien in diesen Ordner legen und `Skip` in `GoldenFileSigningTests` entfernen.

## Automatischer Gegenpart

- Normalisierung: `tools/reference/v3hash_reference.py` (unabhängige Spec-Implementierung,
  Cross-Check-Werte in `VbaContentHasherTests` gepinnt).
- Roundtrip: `VbaProjectSignerTests` (Signieren → SignedCms-Prüfung → Contents-Hash-Bindung).
- Betriebs-Checks (manuell): TC-28 (Office zeigt Signatur gültig), TC-31 (kein Key-Material
  im Container), TC-32 (Netzwerk-Isolation).
