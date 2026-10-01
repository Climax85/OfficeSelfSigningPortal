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
   Anschließend auf der Testmaschine in **beiden** Stores installieren — `Root` allein reicht nicht:
   - `Root` (LocalMachine, Admin) → Signatur-Kette prüft als gültig (Erwartung TC-28)
   - `TrustedPublisher` (CurrentUser) → Office aktiviert Makros ohne Prompt, an jedem Ort
   ```powershell
   $cert = Get-Item Cert:\CurrentUser\My\<Thumbprint>
   # Root (LocalMachine, Admin):
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
   $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
   # TrustedPublisher (CurrentUser):
   $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher","CurrentUser")
   $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
   ```
2. Datei in Office öffnen → VBA-Editor → Extras → Digitale Signatur → Zertifikat wählen → speichern.
   (Alternativ signtool + Office-SIPs, siehe Research R2 — drei Durchläufe Legacy/Agile/V3.)
3. Dateien in diesen Ordner legen und `Skip` in `GoldenFileSigningTests` entfernen.
   ✅ **Erledigt (Ticket 08):** `golden.xlsm`, `golden.docm` und `golden.pptm` liegen vor;
   die `GoldenFileSigningTests` sind aktiv und grün (Byte-für-Byte-Digest-Vergleich gegen
   die in den Office-Signaturen eingebetteten V3-SourceHashes, AK-51/TC-33).
   Die Digest-Regel weicht an zwei Stellen von der MS-OVBA-Spec ab (REGISTERED-Libid als
   UTF-16 mit Zeichenzahl, finaler Zeilenrest wird verworfen) — siehe Klassendokumentation
   `VbaContentHasher` und Beweisskript `.scratch/v3_exp/epplus_exact.py`.

## Makro-Prompt beim Öffnen (Wissenswert)

Der Excel-Prompt „Makros aktivieren?" ist **pfadbasiert**, nicht dateibasiert: Excel
merkt sich pro Dateipfad im Benutzerprofil („Vertrauenswürdige Dokumente"), dass
Makros dort einmal aktiviert wurden. Ein bit-identisches Kopieren in einen neuen
Ordner erzeugt daher wieder einen Prompt — das ist kein Signaturdefekt. Erst das
Zertifikat im Store `TrustedPublisher` bewirkt, dass die Datei an **jedem** Ort
ohne Prompt öffnet.

Für die Fixture-Erzeugung selbst ist das irrelevant (die Tests lesen nur Bytes,
Makros werden nie ausgeführt) — aber TC-28 („Office zeigt Signatur gültig") setzt
den Zielzustand mit beiden Stores als Maschinen-Setup voraus (siehe Hinweis in
`test-cases.md`).

## Automatischer Gegenpart

- Normalisierung: `tools/reference/v3hash_reference.py` (unabhängige Spec-Implementierung,
  Cross-Check-Werte in `VbaContentHasherTests` gepinnt).
- Roundtrip: `VbaProjectSignerTests` (Signieren → SignedCms-Prüfung → Contents-Hash-Bindung).
- Betriebs-Checks (manuell): TC-28 (Office zeigt Signatur gültig), TC-31 (kein Key-Material
  im Container), TC-32 (Netzwerk-Isolation).
