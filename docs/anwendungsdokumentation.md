# Anwendungsdokumentation — `OfficeSelfSigningPortal`

> **Dokumentennummer:** `OSSP-001`
> **Version:** `1.0`
> **Gültig ab:** `2025-09-27`
> **Verantwortlich:** `Patrick (Nachname nachtragen)`
> **Technischer Ansprechpartner:** `Patrick (Nachname nachtragen)`
> **Genehmigt durch:** `Fachbereichsleiter (Name ausstehend)`
> **Nächster Review:** `2026-09-27`
> **Repository / Pfad:** `C:/DEV/ki/OfficeSelfSigningPortal`

---

## 1. Metadaten *(Pflicht)*

| Feld | Inhalt |
|---|---|
| Anwendungsname | `OfficeSelfSigningPortal` |
| Kurzbeschreibung | Self-Service-Portal zur automatisierten Analyse und digitalen Signierung von MS-Office-Makros (.xlsm, .docm, .pptm) mit automatischer Analyse (AMSI, ClamAV, statische VBA/YARA-Analyse) und manuellem Review-Workflow bei Verdachtsfällen |
| Verantwortlicher Fachbereich | `IT-Sicherheit / Fachbereiche mit Makro-Bedarf` |
| Technischer Verantwortlicher | `Patrick (Nachname nachtragen)` |
| Einsatzart | `Webanwendung` |
| Technologiestack | `C# / .NET (LTS) / ASP.NET Core / EF Core / PostgreSQL / .NET Aspire / RabbitMQ (MassTransit)` |
| Betriebsmodus | `On-Premise` |
| Kritikalität | `mittel` |
| Schutzbedarf | `integer` |
| Letzter Sicherheitsreview | `— (erste Dokumentation)` |

**BSI/ISO-Bezug:** APP.7.A1 (Planung), A.5.37 (Documented operating procedures)

---

## 2. Zweck, Betriebseigner, Daten & Schutzbedarf *(Pflicht)*

### 2.1 Geschäftlicher Zweck
- Die Anwendung löst das Problem, dass MS-Office-Makros in Unternehmen entweder global blockiert werden (Produktivitätsverlust) oder ungeprüft laufen (Sicherheitsrisiko). Mitarbeitende laden Makro-Dateien (.xlsm, .docm, .pptm) in ein Self-Service-Portal; die Dateien werden automatisiert analysiert (AMSI, ClamAV, statische VBA/YARA-Analyse) und bei Freigabe digital signiert, sodass sie in der Office-Umgebung der Organisation vertrauenswürdig ausführbar sind. Verdachtsfälle gehen in einen manuellen Review-Workflow.
- Primäre Nutzer: Mitarbeitende (Einreicher), Sicherheits-/Makro-Prüfer (Bearbeiter im Review-Workflow), Administratoren (Portalverwaltung). Stakeholder: IT-Sicherheit, Fachbereiche mit Makro-Bedarf.
- Geschäftskritikalität: Ausfall behindert die Produktivität (Makro-Signierung fällt aus), stoppt aber keine Kerngeschäftsprozesse. Kompromittierung des Signing-Schlüssels hätte schwerwiegende Folgen (Signierung bösartiger Makros mit Vertrauensstellung der Organisation).

### 2.2 Betriebseigner und Verantwortlichkeiten
| Rolle | Name | Verantwortung |
|---|---|---|
| Betriebseigner | Patrick (Nachname nachtragen) | Fachliche Verantwortung, Anforderungen, Budget |
| Technischer Verantwortlicher | Patrick (Nachname nachtragen) | Architektur, Betrieb, Sicherheitsupdates |
| Secure-Coding-Beauftragter | Patrick (Nachname nachtragen) | Sicherheitsreviews, Schwachstellenmanagement |
| Betrieb / DevOps | Patrick (Nachname nachtragen) | Deployment, Monitoring, Backup |

### 2.3 Verarbeitete Daten und Schutzbedarf
| Datenkategorie | Beispiele | Schutzbedarf | Speicherort |
|---|---|---|---|
| Upload-Dokumente | .xlsm/.docm/.pptm inkl. enthaltener Geschäftsdaten | hoch | PostgreSQL bzw. Datei-Volume (finale Festlegung in der Spezifizierung) |
| Analyseergebnisse | AMSI/AV-Befunde, YARA-Hits, VBA-Analyse-Reports | mittel | PostgreSQL |
| Benutzerkonten & Audit-Daten | Einreicher, Bearbeiter, Signierentscheidungen, Zeitstempel | mittel | PostgreSQL |

**BSI/ISO-Bezug:** APP.7.A6 (Anforderungen & Sicherheitsprofil), A.8.26 (Application Security Requirements), A.8.12 (Data Leakage Prevention)

---

## 3. Sicherheitsprofil / Risiko- und Bedrohungsmodell *(Pflicht)*

### 3.1 Sicherheitsanforderungen

*Status: Wird in den Feature-Workflows (Threat Model, Spezifizierung) erarbeitet und über `merge-app-docs` nachgetragen.*

#### Vertraulichkeit

*Status: offen — Leitfragen werden im Threat-Model-Prozess beantwortet.*

#### Integrität

*Status: offen — Leitfragen werden im Threat-Model-Prozess beantwortet.*

#### Verfügbarkeit

*Status: offen — Leitfragen werden im Threat-Model-Prozess beantwortet.*

#### Audit-Nachweis

*Status: offen — Leitfragen werden im Threat-Model-Prozess beantwortet.*

#### Übersicht: Sicherheitsanforderungen
| ID | Kategorie | Anforderung | Begründung / Bezug | Status |
|---|---|---|---|---|
| SA-01 | | | | |

### 3.2 Bedrohungsmodell *(Threat Modeling)*

*Status: Wird featureweise als STRIDE-Threat-Model erarbeitet und hier konsolidiert nachgetragen.*

| ID | Bedrohung | Asset | Auswirkung | Risiko | Gegenmaßnahme | Status |
|---|---|---|---|---|---|---|
| TM-01 | | | | | | |

### 3.3 Akzeptierte Risiken

*Status: Noch keine Risiken akzeptiert. Aufnahme erfolgt mit Begründung und Verantwortlichem über den Feature-Workflow.*

**BSI/ISO-Bezug:** CON.8.A21 (Bedrohungsmodellierung), CON.8.A22 (Sicherer Software-Entwurf), APP.7.A6, A.8.27 (Secure Architecture)

---

## 4. Architektur & Architektur-Entscheidungen *(Pflicht)*

### 4.1 Übersichtsdiagramm

*Status: Entsteht in der Spezifizierungsphase (C4-Container-Diagramm: AppHost, WebUI, WorkerService, SigningService, PostgreSQL, RabbitMQ).*

### 4.2 Technologie-Stack

*Status: Detailtabelle (inkl. Versionsstände) wird mit der Umsetzung nachgetragen.*

| Schicht | Technologie | Version | Bemerkung |
|---|---|---|---|
| Frontend | | | |
| Backend | | | |
| Datenbank | | | |
| Komponenten / Bibliotheken | | | |

### 4.3 Architektur-Entscheidungen (ADRs)
| ID | Entscheidung | Kontext | Konsequenz | Datum |
|---|---|---|---|---|
| ADR-01 | | | | |

**BSI/ISO-Bezug:** CON.10.A11 (Softwarearchitektur), CON.8.A12 (Ausführliche Dokumentation), A.8.27 (Secure Architecture)

---

## 5. Datenflüsse & Schnittstellen *(Pflicht)*

*Status: Externe und interne Schnittstellen werden featureweise als `IF-nn` im Threat Model erfasst und hier konsolidiert.*

### 5.1 Externe Schnittstellen
| ID | Name | Protokoll | Authentisierung | Daten | Datenfluss | Verantwortlich | Dokumentation |
|---|---|---|---|---|---|---|---|
| IF-01 | | | | | | | |

### 5.2 Interne Schnittstellen
| ID | Komponente A | Komponente B | Protokoll | Daten | Bemerkung |
|---|---|---|---|---|---|
| IF-10 | | | | | |

### 5.3 Datenflussdiagramm

*Status: Entsteht auf Anwendungsebene nach der Spezifizierung.*

**BSI/ISO-Bezug:** APP.7.A3 (Sicherheitsfunktionen zur Systemintegration), APP.3.1.A11 (Schnittstellen), A.5.14 (Information Transfer)

---

## 6. Authentisierung & Autorisierung *(Pflicht)*

*Status: Verfahren (z. B. OIDC/SSO gegen bestehendes Unternehmens-IAM) und Rollenmodell werden in der Spezifizierung festgelegt und hier nachgetragen.*

### 6.1 Authentisierung

*Status: offen.*

### 6.2 Autorisierung / Berechtigungskonzept

*Status: offen.*

| Rolle | Berechtigungen | Geltungsbereich |
|---|---|---|
| | | |

### 6.3 Service-Accounts und technische Benutzer
| Account | Verwendung | Berechtigungsumfang | Verantwortlicher |
|---|---|---|---|
| | | | |

**BSI/ISO-Bezug:** CON.10.A1 (Authentisierung), APP.3.1.A1, ORP.4 (IAM), A.8.2 / A.8.5 (Access Control)

---

## 7. Berechtigungsmanagement *(Pflicht)*

### 7.1 Prozess für Zuweisung, Änderung und Entzug
- Beantragung: Zutritt zum Portal über die bestehende Unternehmens-Authentisierung (Verfahren siehe §6, noch offen); die Reviewer-Rolle wird vom Technischen Verantwortlichen auf Antrag (GitHub-Issue oder E-Mail) vergeben.
- Genehmigung & Nachweis: Technischer Verantwortlicher; Nachweis über GitHub-Issue.
- Regelmäßiges Review: halbjährlich durch den Technischen Verantwortlichen.

### 7.2 Notfallzugriffe
- Break-Glass: temporärer Admin-Zugang durch den Technischen Verantwortlichen, Protokollierung im Audit-Log.

### 7.3 Inaktive Kennungen
- Sperrung bei Austritt über den IAM-Prozess des Unternehmens; Dormant-Accounts werden im halbjährlichen Review gesperrt.

**BSI/ISO-Bezug:** ORP.4 (Identitäts- und Berechtigungsmanagement), A.5.18 (Access Rights)

---

## 8. Kryptografie & Schlüsselmanagement *(Optional — nur wenn Kryptografie genutzt wird)*

*Status: Die Anwendung signiert Makros digital (Kerndienst, Zugriff auf KMS/Zertifikate). Algorithmen, Schlüssellängen und Schlüsselmanagement werden im Feature-Workflow (Threat Model) festgelegt und hier nachgetragen.*

### 8.1 Eingesetzte kryptografische Verfahren
| Zweck | Algorithmus | Schlüssellänge | Bibliothek |
|---|---|---|---|
| Signatur (vbaProject.bin) | | | |
| Transportverschlüsselung | TLS 1.2/1.3 | | |
| Hashing (Datei-Integrität) | | | |

### 8.2 Schlüsselmanagement

*Status: offen — Schlüsselgenerierung, -speicherung (KMS), -rotation und Verantwortlichkeiten werden im Threat Model festgelegt. Hartcodierte Schlüssel im Quellcode sind untersagt.*

**BSI/ISO-Bezug:** CON.1 (Kryptokonzept), A.8.24 (Use of Cryptography)

---

## 9. Logging & Monitoring *(Pflicht)*

### 9.1 Log-Quellen und Ereignisse
- Geloggte Ereignisse: Einreichung (Prüfauftrag), Analyseergebnis, Review-Entscheidung, Signierung, Login/Logout, Berechtigungsänderungen, Fehler und Dead-Letter-Queue-Ereignisse.
- Telemetrie: OpenTelemetry über den .NET-Aspire-AppHost; strukturiertes Logging via `ILogger` (keine String-Interpolation in Log-Templates).

### 9.2 Log-Schutz und Aufbewahrung
- Speicherort und -dauer: Operational Logs 90 Tage; audit-relevante Ereignisse (Signierentscheidungen, Berechtigungsänderungen, Logins) 1 Jahr.
- Schutz: keine Secrets und keine Inhalte aus Upload-Dokumenten in Logs — nur Datei-IDs und Hashwerte.

### 9.3 Monitoring und Alarmierung
- Überwachte Metriken: RabbitMQ-Queue-Tiefe, Dead-Letter-Queue-Belegung, Signierlatenz, Fehlerraten der Analysedienste.
- Alarmierung: zunächst an den Technischen Ansprechpartner; Eskalationskette wird mit dem Betrieb verfestigt.

**BSI/ISO-Bezug:** CON.10.A13 (Fehlerbehandlung), APP.3.1.A22 (Revision), A.8.15 (Logging), A.8.16 (Monitoring)

---

## 10. Konfiguration & Hardening *(Pflicht)*

*Status: Betriebsumgebung, Hardening-Konfiguration und Checklisten entstehen mit der Umsetzung (Aspire-Topologie, Container-Hardening) und werden hier nachgetragen.*

### 10.1 Betriebsumgebung

*Status: offen.*

### 10.2 Sicherheitsrelevante Konfigurationen
| Bereich | Konfiguration | Begründung |
|---|---|---|
| HTTP-Header | | |
| Cookies | | |
| Datenbank | | |
| Dateisystem | | |
| Netzwerk | | |

### 10.3 Hardening-Checkliste

*Status: offen — Verweis auf stack-spezifische Vorgaben (siehe Anhang A) erfolgt mit der Umsetzung.*

**BSI/ISO-Bezug:** APP.3.1.A12 (Sichere Konfiguration), APP.3.1.A21 (Sichere HTTP-Konfiguration), CON.8.A5 (Sicheres Systemdesign)

---

## 11. Patch- und Schwachstellenmanagement *(Pflicht)*

### 11.1 Verantwortlichkeiten
- Überwachung: Technischer Ansprechpartner (Dependabot-Meldungen, BSI- und Herstellerhinweise).
- Entscheidung über Einspielung: Technischer Ansprechpartner; Ablehnungen werden im Entscheidungslog dokumentiert.

### 11.2 Patch-Prozess
- Quellen: Dependabot (GitHub) für NuGet-Pakete; BSI- und Herstellerhinweise für Plattformkomponenten (RabbitMQ, PostgreSQL, ClamAV).
- Zeitliche Ziele: kritisch ≤ 7 Tage, hoch ≤ 30 Tage, mittel ≤ 90 Tage.
- Test und Rollback: Test-Suite mit Testcontainers (PostgreSQL, RabbitMQ); Rollback über Container-Redeploy mit vorheriger Version.

### 11.3 Schwachstellen- und Patch-Entscheidungslog
| Datum | Schwachstelle | Komponente | Risiko | Entscheidung | Begründung | Verantwortlicher |
|---|---|---|---|---|---|---|
| | | | | | | |

**BSI/ISO-Bezug:** OPS.1.1.3.A15 (Aktualisierung), A.8.8 (Management of technical vulnerabilities)

---

## 12. Änderungshistorie / Changelog *(Pflicht)*

| Version | Datum | Änderung | Autor | Genehmigt durch | Sicherheitsrelevant |
|---|---|---|---|---|---|
| 1.0 | 2025-09-27 | Initiale Version | Patrick (Nachname nachtragen) | Fachbereichsleiter (Name ausstehend) | Nein |
| 1.1 | 2026-09-30 | §14: Deployment-Profile (`baseline`/`hardened`), Runbook-Einträge OP-01–OP-12, manuelle Betriebs-Checks (Ticket 12) | Patrick Wels | — | Ja |

**BSI/ISO-Bezug:** OPS.1.1.3.A11 (Kontinuierliche Dokumentation), A.8.32 (Change Management)

---

## 13. Audit- und Testhistorie *(Pflicht)*

### 13.1 Durchgeführte Sicherheitsprüfungen
| Datum | Art der Prüfung | Durchgeführt von | Ergebnis | Bemerkung |
|---|---|---|---|---|
| 2025-09-27 | Initiale Dokumenterstellung | Intern | — | Erste Version; Security-Prüfungen (Code-Review, SAST/SCA) folgen mit der Umsetzung |

### 13.2 Abweichungs- und Maßnahmenverfolgung
| ID | Finding | Risiko | Maßnahme | Frist | Status |
|---|---|---|---|---|---|
| | | | | | |

**BSI/ISO-Bezug:** APP.3.1.A22 (Penetrationstest und Revision), A.8.29 (Security Testing), A.8.34 (Protection during audit testing)

---

## 14. Betriebshandbuch / Runbook *(Pflicht)*

*Status: Start-/Stopp-Anleitungen, Backup- und Wiederanlaufverfahren entstehen mit der Umsetzung (Aspire-Orchestrierung) und werden hier nachgetragen.*

### 14.1 Starten, Stoppen, Neustarten

*Status: offen.*

### 14.2 Backup & Wiederanlauf

*Status: offen.*

### 14.3 Fehlersuche und Eskalation

*Status: offen.*

### 14.4 Business-Continuity-Hinweise

*Status: offen.*

### 14.5 Deployment-Profile `baseline` / `hardened` (Anhang E, AK-57)

Das Deployment wird in zwei Profilen betrieben (Festlegung Anhang E der Anforderungen):

| Profil | Enthalten | AMSI-Verhalten | Einsatz |
|---|---|---|---|
| `baseline` (Default) | WebUI, WorkerService (ClamAV + YARA + Heuristik), SigningService, PostgreSQL, RabbitMQ, Keycloak (Dev-IdP), MailPit (Dev-SMTP) | `EngineResult(amsi, Absent)` — das Verdict stammt stets aus der Baseline (AK-46) | Standardbetrieb |
| `hardened` | wie `baseline`, zusätzlich `AmsiScanBridge`-Stage auf einem Windows-Host **außerhalb** Aspire (ADR-0004) | AMSI-Ausfall/Timeout → `Inconclusive` → Review-Pflicht, kein Auto-Signing (TM-15/AK-26, TC-19) | Erhöhte Bedrohungslage |

**Profilwahl (Aspire-AppHost):** Das Profil wird in dieser Priorität aufgelöst:
Kommandozeile `--Deployment:Profile=hardened` → Umgebungsvariable `Deployment__Profile` →
`appsettings.json` (`Deployment:Profile`) → Default `baseline`. Ein unbekannter Wert verweigert
den AppHost-Start fail-fast. Beispiel hardened:

```bash
# Bridge-Endpunkt betriebsseitig bereitstellen (User-Secret oder Umgebungsvariable),
# sonst verweigert der AppHost-Start:
dotnet user-secrets set --project src/OfficeSelfSigningPortal.AppHost "Parameters:amsi-bridge-url" "https://<windows-host>:<port>"
Deployment__Profile=hardened dotnet run --project src/OfficeSelfSigningPortal.AppHost
```

**Netzwerk-Policy im Profil `hardened` (REQ-14, TM-19):** Die Sign-Queue
(`ossp.sign-macro-requested`) wird ausschließlich von der AnalysisSaga publiziert.
Strukturelle Isolation: Der SigningService besitzt keinen HTTP-Endpunkt und ist aus dem
Front-End-Netz nicht erreichbar; zusätzlich verifiziert der SigningService-Guard vor jeder
Signatur den Saga-Status `SignierungAngefragt` und den `ContentSha256` (Verteidigung in der
Tiefe, TM-19). Produktiv ist die Broker-Policy zu ergänzen: dedizierte RabbitMQ-Credentials
für den SigningService mit Queue-Permissions auf `ossp.sign-macro-requested` — die
Front-End-Credentials erhalten keinen Zugriff auf die Sign-Queue.

**Profil-Smoke-Checks** (nach jedem Profilstart bzw. nach Änderungen am Stack):

| # | Check | Erwartetes Ergebnis `baseline` | Erwartetes Ergebnis `hardened` |
|---|---|---|---|
| S1 | Stack startet vollständig (Dashboard: alle Ressourcen Healthy) | ja | ja |
| S2 | Upload einer sauberen Makrodatei durchläuft Scan → Signierung → `Signiert` | ja | ja |
| S3 | Scan-Ergebnis/Findings: AMSI-Stage | `Absent` (AK-46, TC-18) | `Ok` bei erreichbarer Bridge |
| S4 | Bridge gestoppt → Upload im Profil | n/a | Verdict `Inconclusive`, Vorgang `ReviewAusstehend`, kein Auto-Signing (TC-19) |
| S5 | DLQ `ossp.scan-requested_error` | leer | leer |

### 14.6 Runbook-Einträge (OP-01–OP-12)

Die operativen Festlegungen des Threat Models (OP-nn, bestätigt 2025-09-27) und ihre
Verifikation im Betrieb:

| OP | Thema | Festlegung (Kurz) | Verifikation / Verweis |
|---|---|---|---|
| OP-01 | Stack-Inventar | Festgelegter Technologie- und Komponentenstack | §4.2; Container-Versionen im Dashboard |
| OP-02 | Authentisierung | ausschließlich OIDC (produktiv Entra ID, lokal Keycloak), MFA am IdP, keine lokalen Konten | Login nur per IdP-Redirect; lokale Konten existieren nicht |
| OP-03 | Autorisierung / SoD | RBAC per IdP-Gruppen (`Einreicher`/`Bearbeiter`/`Admin`); Einreicher kann eigene Vorgänge nicht freigeben | Negativtest: Freigabe eigener Vorgänge wird abgelehnt (REQ-17) |
| OP-04 | Rollenvergabe | ausschließlich per IdP-Gruppenmitgliedschaft; das Portal vergibt keine Rollen | Rollenänderung nur in Keycloak/Entra; Portal-DB enthält keine Rollentabelle |
| OP-05 | Kryptografie | SHA-256 (VBA-V3-Hash, Audit-Kette), PKCS#7/CMS SignedCms (SpcIndirectDataContent), TLS 1.2+ extern | §8.1; Signatur-Hashes und Audit-Kettenprüfung |
| OP-06 | Schlüsselmanagement | Codesigning-P12 in CyberArk Conjur (JWT-AuthN, base64-Variable), Abruf pro Signing, `EphemeralKeySet`, Wipe nach Verwendung, Rotation vault-seitig; Dev: lokales Zertifikat (User-Secret) | §8.2, ADR-0002; TC-31, TC-35 |
| OP-07 | Audit-Trail | append-only mit SHA-256-Hash-Kette, Aufbewahrung 1 Jahr, Kettenprüfung bei Admin-Abruf | §9.2; Admin-Abruf prüft Kette |
| OP-08 | Upload-Restriktionen | max. 25 MB (konfigurierbar), nur .xlsm/.docm/.pptm, Zip-Bomb-/Polyglot-Prüfung in der Ingestion; E-Mail nur Status + Link | Negativtests Ingestion (TC-05/06); MailPit-Inhalt prüfen |
| OP-09 | Hardening | SigningService netzwerk-isoliert, Container non-root, kein Key-Material auf Disk, Sign-Queue nur von der Saga, YARA-Regelset versioniert im Image | TC-31, TC-32; §10.3 |
| OP-10 | Betriebsszenarien | Vault-Ausfall, AMSI-Bridge-Ausfall, DLQ-Handling, Retention, Conjur-Rotation | Detailverfahren siehe unten |
| OP-11 | Externe Schnittstellen | nur OIDC-Login (IF-01–IF-03) und SMTP (IF-07); alle übrigen Datenflüsse intern | §5.1; Netz-Scan/Expose-Check |
| OP-12 | Regelpflege | kuratiertes YARA-Subset (Neo23x0/signature-base), Regelname→Score-Mapping, `scoreVersion`-Pflege, periodische Kalibrierung (Backlog) | `Scanning:Scoring:ScoreVersion` beim Regelupdate anheben |

**OP-10a — Vault-Ausfall (CyberArk Conjur), TM-16:**
- Verhalten: Polly Retry (exponentiell + Jitter) + Circuit Breaker (ADR-0002); offener Circuit
  lässt Signieraufträge in der Queue als persistierenden Puffer stauen — kein Verlust.
- Erkennen: Circuit-Breaker-Log im SigningService; wachsende Queue-Tiefe `ossp.sign-macro-requested`.
- Handlung: Conjur-Verfügbarkeit prüfen (AuthN-JWT, Netzweg); nach Wiederherstellung laufen
  die Aufträge automatisch nach (MassTransit-Redelivery). Bleibt der Ausfall über das
  Retry-Limit hinaus bestehen, landen die Aufträge in der Fault-Queue und der Vorgang geht
  in `Fehler` (REQ-22) — Betriebs-Alarm, manuelle Requeue nach Ursachenbeseitigung.
- Nicht-transient: HTTP 401/404 geht früh in die Fault-Queue (kein Retry — Konfiguration prüfen).

**OP-10b — AMSI-Bridge-Ausfall (nur Profil `hardened`), TM-15/AK-26:**
- Verhalten: Bridge nicht erreichbar/Timeout (Deadline 15 s, `Scanning:Engines:AmsiStageTimeout`)
  → AMSI-Stage `Failed` → Verdict `Inconclusive` → Vorgang `ReviewAusstehend`. **Kein
  Auto-Signing** — die Baseline-Engines (ClamAV/YARA/Heuristik) allein triggern keine Signierung.
- Erkennen: `Failed`-Eintrag der AMSI-Stage im Scan-Ergebnis; gehäufte Vorgänge in `ReviewAusstehend`.
- Handlung: Bridge-Dienst auf dem Windows-Host prüfen/neustarten; bestehende Vorgänge in
  `ReviewAusstehend` manuell durch den Bearbeiter entscheiden (Freigabe erzeugt keinen neuen
  Scan — die Entscheidung dokumentiert den AMSI-Ausfall).

**OP-10c — DLQ-Handling (`ossp.scan-requested_error`), REQ-22:**
- Verhalten: Nach Retry-Limit geht der Vorgang in `Fehler`; DLQ-Eintrag + Audit-Ereignis.
- Erkennen: Queue-Tiefe `ossp.scan-requested_error` > 0; Dashboard/Vorgangsliste auf `Fehler`.
- Handlung: Ursache im WorkerService-Log (Stage-Fehler, Parser-Error, verschlüsseltes VBA-Projekt)
  beheben; Vorgang ggf. erneut einreichen lassen (Einreicher). Nie ohne Ursachenklärung blind requeueen.

**OP-10d — Retention (REQ-19):**
- Verhalten: Täglicher Retention-Job (`Retention:BlobRetentionDays`, Default 90) löscht
  Original- und Signatur-Blobs ab dem Audit-Zeitstempel des Eintritts von `Signiert`;
  jede Löschung wird append-only auditprotokolliert (Kategorie `deletion`, Akteur
  `system:retention`). Scan-Ergebnisse und Audit-Metadaten bleiben bestehen (Audit 1 Jahr, OP-07).
- WebUI: Download des Originals antwortet nach Löschung mit `410 Gone` (Download-Fenster
  `Downloads:SignedDownloadRetentionDays`, Default 90).
- Erkennen/Handlung: Löschfehler (z. B. Audit-Schreibfehler, REQ-18-Fehlerfall) verhindern die
  Löschung idempotent — Vorgang verbleibt vollständig, Audit-Eintrag prüfen, Betrieb benachrichtigen.

**OP-10e — Conjur-Rotation (AK-58, OP-06):**
- Ablauf: Das Codesigning-P12 wird **vault-seitig** rotiert (neue base64-Variable in Conjur).
  Kein App-Restart, kein Deploy erforderlich: Der SigningService ruft das Zertifikat pro
  Signing-Vorgang frisch ab und verwischt es nach Verwendung (kein Cache, kein Disk-Zugriff).
- Handlung: Neues Zertifikat im Portal-Signaturpfad verifizieren (Upload → Signiert →
  Signatur in Office gültig, TC-28). Bei Provider-Ausfall Fallback `Signing:KeyProvider:Provider=AzureKeyVault`
  konfigurieren (Betriebs-Backlog).

### 14.7 Manuelle Betriebs-Checks

Nicht automatisierbare Checks aus den Testfällen — jährlich sowie nach sicherheitsrelevanten Änderungen:

| TC | Check | Verfahren | Erwartetes Ergebnis |
|---|---|---|---|
| TC-28 | Signaturanzeige in Office | Signierte .xlsm in vertrauender Office-Installation öffnen (Golden Fixtures: `examples/golden/`) | VBA-Projekt-Signatur wird als gültig angezeigt (REQ-16) |
| TC-31 | Key-Material-Inspektion | `docker exec` in den SigningService-Container: Dateisystem nach P12/Key/Temp-Dateien durchsuchen (nach einer Signierung) | Kein Key-Material, kein P12, keine Zertifikats-Temp-Datei auffindbar (REQ-15, AC-03) |
| TC-32 | Netzwerk-Isolations-Negativtest | Aus dem WebUI-/Front-End-Container Verbindungsversuch zum SigningService (kein HTTP-Endpunkt vorhanden; ggf. Broker-Port-Scan) | Keine Erreichbarkeit (REQ-14, AC-03) |
| TC-43 | Repo-/CI-Log-Scan auf Secrets | Scan des Repos und der CI-Logs (Muster: `BEGIN .* PRIVATE KEY`, P12-Passwörter, `Parameters__`-Werte) | Kein Private-Key-Material, kein Dev-Credential auffindbar (REQ-24, AC-03) |

**BSI/ISO-Bezug:** CON.8.A12 (Betriebsdokumentation), A.5.37 (Documented operating procedures), A.5.29 / A.5.30 (Continuity)

---

## Anhang A — Stack-spezifische Ergänzungen für ASP.NET 8 *(Optional, bei Web-Apps)*

### A.1 Web-Security-Hardening
- [ ] CSP-Header konfiguriert
- [ ] HSTS aktiviert
- [ ] Anti-CSRF-Token vorhanden
- [ ] Sichere Cookie-Attribute (Secure, HttpOnly, SameSite)
- [ ] Input-Validierung serverseitig
- [ ] Output-Encoding gegen XSS
- [ ] Sichere Session-Konfiguration

### A.2 Deployment & Hosting

*Status: IIS/Kestrel-/Container-Konfiguration, Reverse-Proxy und Health-Checks werden mit der Umsetzung dokumentiert.*

### A.3 ASP.NET-spezifische Abhängigkeiten

*Status: NuGet-Paketliste mit Versionsständen und EF-Core-Konfiguration wird mit der Umsetzung nachgetragen.*

**BSI/ISO-Bezug:** CON.10.A1–A16, APP.3.1.A21, A.8.28

---

## Anhang D — Mapping: Kapitel → BSI / ISO-27001:2022 *(Pflicht)*

| Kapitel | BSI-Anforderungen | ISO-27001:2022-Kontrollen |
|---|---|---|
| 1. Metadaten | APP.7.A1 | A.5.37 |
| 2. Zweck, Daten & Schutzbedarf | APP.7.A6 | A.8.26, A.8.12 |
| 3. Sicherheitsprofil / Bedrohungsmodell | CON.8.A21, CON.8.A22, APP.7.A6 | A.8.27 |
| 4. Architektur & ADRs | CON.10.A11, CON.8.A12, CON.8.A22 | A.8.27 |
| 5. Datenflüsse & Schnittstellen | APP.7.A3, APP.3.1.A11 | A.5.14 |
| 6. Authentisierung & Autorisierung | CON.10.A1, APP.3.1.A1, ORP.4 | A.8.2, A.8.5 |
| 7. Berechtigungsmanagement | ORP.4 | A.5.18 |
| 8. Kryptografie & Schlüsselmanagement | CON.1 | A.8.24 |
| 9. Logging & Monitoring | CON.10.A13, APP.3.1.A22 | A.8.15, A.8.16 |
| 10. Konfiguration & Hardening | APP.3.1.A12, APP.3.1.A21, CON.8.A5 | A.8.27 |
| 11. Patch- und Schwachstellenmanagement | OPS.1.1.3.A15 | A.8.8 |
| 12. Änderungshistorie | OPS.1.1.3.A11 | A.8.32 |
| 13. Audit- und Testhistorie | APP.3.1.A22 | A.8.29, A.8.34 |
| 14. Betriebshandbuch | CON.8.A12 | A.5.37, A.5.29, A.5.30 |
| Anhang A (ASP.NET) | CON.10.A1–A16 | A.8.28 |
| Anhang B (Qt 6 C++) | CON.8.A5 | A.8.28 |
| Anhang C (MS Access / VBA) | APP.4.3, CON.8.A5 | A.8.28 |

---

## Review- und Pflegehinweise *(Pflicht)*

- Diese Anwendungsdokumentation muss **jährlich** oder bei **sicherheitsrelevanten Änderungen** reviewt und aktualisiert werden.
- Bei sicherheitsrelevanten Änderungen ist die [Pull-Request-Checkliste](../vorlagen/pr-checkliste.md) anzuwenden.
- Änderungen werden im Kapitel 12 (Changelog) nachvollziehbar dokumentiert.
- Freigabe und Review durch Anwendungsverantwortlichen und Secure-Coding-Beauftragten.
