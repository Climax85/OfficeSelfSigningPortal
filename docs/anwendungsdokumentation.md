# Anwendungsdokumentation — `OfficeSelfSigningPortal`

> **Dokumentennummer:** `OSSP-001`
> **Version:** `1.2`
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
| Letzter Sicherheitsreview | `2026-10-01` |

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
| SA-01 | Integrität | Verdachtsfälle (Scan-Ergebnis Suspicious) werden durch einen menschlichen Bearbeiter vor der Signierung geprüft. | Epic #7 (REQ-03) | umgesetzt |
| SA-02 | Audit-Nachweis | Administratoren können den vollständigen, manipulationssicheren Audit-Trail aller Vorgänge und Entscheidungen durchsuchen. | Epic #7 (REQ-07) | umgesetzt |
| SA-03 | Vertraulichkeit | Die Authentifizierung erfolgt über generisches OIDC (lokal: Keycloak-Container im Aspire-AppHost mit Realm-Import; produktiv: Entra ID), Rollen (`Einreicher`, `Bearbeiter`, `Admin`) werden ausschließlich aus IdP-Gruppen-Claims abgeleitet und nie im Portal vergeben. | Epic #7 (REQ-09) | umgesetzt |
| SA-04 | Verfügbarkeit | Die Ingestion akzeptiert nur .xlsm/.docm/.pptm bis 25 MB (konfigurierbar), lehnt passwortgeschützte Dateien ab, meldet korrupte Dateien als Fehlerzustand und weist makrofreie Dateien mit Hinweis zurück. | Epic #7 (REQ-10) | umgesetzt |
| SA-05 | Integrität | Der WorkerService führt die Analyse mit ClamAV, YARA (kuratiertes signature-base-Subset, Regelname→Score-Mapping per Config) und einem eigenen Heuristik-Scorer (mraptor-Logik + Keyword-Gruppen + Obfuscation, OpenMcdf-Extraktion) aus; die AMSI-Bridge ist ein optionaler Engine-Stage (Deployment-Profil). | Epic #7 (REQ-12) | umgesetzt |
| SA-06 | Integrität | Die Verdict-Policy verdichtet Scan-Ergebnisse zu `Clean` (automatische Signierung), `Suspicious` (Review-Pflicht) oder `Malicious` (Ablehnung plus Benachrichtigung des Security-Teams). | Epic #7 (REQ-13) | umgesetzt |
| SA-07 | Vertraulichkeit | Der SigningService ist der einzige Dienst mit Zugriff auf Signier-Keys, läuft netzwerk-isoliert (für das Front-End-Netz nicht erreichbar) und verarbeitet ausschließlich über die Message-Bus gekapselte Signieraufträge. | Epic #7 (REQ-14) | umgesetzt |
| SA-08 | Vertraulichkeit | Der Key-Zugriff läuft über die Abstraktion `ICodeSigningKeyProvider` mit den Implementierungen `LocalDevKeyProvider` (zuerst), `CyberArkConjurKeyProvider` (Produktiv-Primär) und `AzureKeyVaultKeyProvider` (Fallback); Private-Key-Material liegt maximal kurzlebig im Arbeitsspeicher und niemals auf Disk oder im Git. | Epic #7 (REQ-15) | umgesetzt |
| SA-09 | Integrität | Die Signierung erfolgt über den eigenen `VbaProjectSigner` (MS-OVBA-V3-Normalisierung, SHA-256, `SignedCms`, einheitlich .xlsm/.docm/.pptm, Linux-Container, null Lizenzkosten); Fallback hinter `IVbaProjectSigner`: WindowsSigningAgent (signtool + Office-SIPs). | Epic #7 (REQ-16) | umgesetzt |
| SA-10 | Integrität | Der Review-Workflow erlaubt die Entscheidungen `Freigeben`, `Ablehnen` und `Rückfrage`; Separation-of-Duties ist erzwungen — ein Einreicher kann seine eigene Datei nicht freigeben (dann Vier-Augen-Regel). | Epic #7 (REQ-17) | umgesetzt |
| SA-11 | Audit-Nachweis | Alle vorgangsrelevanten Ereignisse (Upload, Scan-Ergebnisse, Review-Entscheidungen, Signierung, Downloads, Löschungen) werden in einer append-only, hash-verketteten Audit-Tabelle mit Zeitstempel und Identität protokolliert. | Epic #7 (REQ-18) | umgesetzt |
| SA-12 | Audit-Nachweis | Ein Retention-Job löscht Original- und Signaturdateien nach 90 Tagen (konfigurierbar), Scan-Ergebnisse und Audit-Metadaten bleiben 1 Jahr append-only bestehen. | Epic #7 (REQ-19) | umgesetzt |
| SA-13 | Verfügbarkeit | Scan- und Signieraufträge haben definierte Retry-Policies (exponentieller Backoff) und landen nach Überschreiten im Dead-Letter-Queue-Pfad mit automatischem Vorgangsstatus `Fehler`. | Epic #7 (REQ-22) | umgesetzt |
| SA-14 | Verfügbarkeit | Die Ingestion prüft Dateien vor der Weitergabe auf Zip-Bomb- und Polyglot-Muster (Größenverhältnis, OLE-Strukturplausibilität) und bricht verdächtige Uploads vor der Scanner-Übergabe ab. | Epic #7 (REQ-23) | umgesetzt |
| SA-15 | Vertraulichkeit | Die lokalen Dev-Credentials (Dev-Codesigning-Zertifikat, Keycloak-Test-User, Test-SMTP) werden als Aspire-Parameter/User-Secrets injiziert und niemals im Repository abgelegt. | Epic #7 (REQ-24) | umgesetzt |

### 3.2 Bedrohungsmodell *(Threat Modeling)*

*Status: Wird featureweise als STRIDE-Threat-Model erarbeitet und hier konsolidiert nachgetragen.*

| ID | Bedrohung | Asset | Auswirkung | Risiko | Gegenmaßnahme | Status |
|---|---|---|---|---|---|---|
| TM-01 | Einreichung mit kompromittiertem Mitarbeiter-Account (Phishing/Account-Diebstahl). | Vertrauensstellung der Organisationssignatur | Schädlinge werden als legitime Vorgänge eingereicht und können signiert werden. | mittel | Authentifizierung ausschließlich via Entra ID mit MFA am IdP (REQ-09); Multi-Engine-Gate vor jeder Signierung (REQ-12/13). | umgesetzt |
| TM-02 | Gefälschte Benachrichtigungs-E-Mails bzw. Missbrauch des Rückfrage-Kanals für Phishing-Inhalte. | Vertrauen der Bearbeiter in Portal-Kommunikation | Bearbeiter werden über Nachrichtenkanäle angegriffen oder der Workflow verstopft. | niedrig | E-Mail ist nie verbindlich (nur Status + Portal-Link, kein Anhang, SMTP-Auth + TLS, REQ-21); Link-/Markup-Filter und Rate-Limit im Rückfrage-Kanal. | umgesetzt |
| TM-03 | Austausch der Datei zwischen Scan und Signierung (TOCTOU auf der Artefakt-Referenz). | Integrität des signierten Inhalts | Eine gescannte saubere Datei wird vor der Signatur gegen eine bösartige getauscht. | mittel | `ContentSha256` (SHA-256 über den Blob) in `ScanRequested`/`SignMacroRequested` führen; SigningService verifiziert den Hash vor der Signatur und bricht bei Abweichung ab (`SignMacroFailed, Retryable: false`). | umgesetzt |
| TM-04 | Manipulation oder Löschung von Audit-Einträgen über direkten Datenbankzugriff. | Nichtabstreitbarkeit (Audit-Trail) | Vorgänge und Entscheidungen sind nachträglich veränderbar, Compliance-Nachweis verloren. | mittel | Append-only-Tabelle mit SHA-256-Hash-Kette (REQ-18); Prüfung der Kette bei Admin-Abruf (AK-07); DB-Zugriff nur aus den Services. | umgesetzt |
| TM-05 | Manipulation von YARA-Regelwerk oder Scoring-Konfiguration. | Verlässlichkeit des Verdicts | Verdachtsfälle werden systematisch unter- oder überbewertet. | niedrig | Kuratiertes, versioniertes Regelset im Container-Image mit `scoreVersion`-Pflichtfeld (Anhang D); Regelname→Score-Mapping als Config unter Versionskontrolle; Änderungen nur per Review. | umgesetzt |
| TM-06 | Manipulation von Scanergebnissen auf dem Transport (Message-Bus). | Integrität der Verdict-Bildung | Falsch positive/negative Verdicts durch eingeschleuste Nachrichten. | niedrig | RabbitMQ ausschließlich im isolierten internen Container-Netz, keine exponierten Endpunkte; Outbox statt direktem Publish (REQ-11). | umgesetzt |
| TM-07 | Bearbeiter bestreitet Review-Entscheidung oder Einreicher bestreitet Upload/Antwort. | Audit-Nachweis | Entscheidungen sind nicht zuordenbar, Rechtssicherheit entfällt. | niedrig | Jede Entscheidung mit IdP-Identität, Zeitstempel und Hash-Ketten-Eintrag (REQ-18, AK-07). | umgesetzt |
| TM-08 | Automatisch signierte Vorgänge ohne nachvollziehbaren Akteur und Evidenz. | Nachvollziehbarkeit des Auto-Signings | Bei Vorfall ist nicht rekonstruierbar, warum signiert wurde. | niedrig | `RequestedBy: "system:auto-sign"` (Anhang A) plus vollständige Scan-Evidenz (Findings, Score, ScoreVersion, EngineStates) im Audit-Trail (REQ-13, AK-13). | umgesetzt |
| TM-09 | Exfiltration des Codesigning-Private-Keys aus dem SigningService. | Signing-Schlüssel | Beliebige Signierung außerhalb des Portals — vollständiger Vertrauensbruch. | mittel | Netzwerk-Isolierung (REQ-14); Key ausschließlich Memory-only mit `EphemeralKeySet`, Abruf pro Vorgang aus Conjur via JWT, Wipe nach Verwendung (REQ-15, ADR-0002); kein Disk-Footprint (AK-15). | offen |
| TM-10 | Einsicht fremder Vorgänge oder Dateiinhalte durch Einreicher oder unberechtigte Bearbeiter. | Vertraulichkeit der eingereichten Inhalte | Interne Dokumente/Makros werden für Unbefugte sichtbar. | mittel | Autorisierung je Vorgang: Einreicher nur eigene Vorgänge, Bearbeiter-Rolle für fremde (REQ-09); Zugriffsprüfung serverseitig je Abruf. | umgesetzt |
| TM-11 | Datenleck über Benachrichtigungs-E-Mails (Inhalte, Anhänge, Metadaten). | Vertraulichkeit der Vorgangsdaten | Interne Befunde oder Dateiinhalte verlassen das Portal ungeschützt. | niedrig | E-Mail transportiert nur Status + Link, niemals Anhänge oder Befunddetails (REQ-21); TLS-Zwang für SMTP. | umgesetzt |
| TM-12 | Dev-Credentials oder Key-Material landet im Repository/CI-Logs. | Entwicklungs-Secrets, ggf. Dev-Signing-Key | Sekrete werden öffentlich, Kompromittierung der Dev-Umgebung. | niedrig | Secrets ausschließlich via Aspire-Parameter/User-Secrets/Env (REQ-24); Repo-Scan als AK (AK-24); Dev-Zertifikat nie im Git (ADR-0003-Kontext). | umgesetzt |
| TM-13 | Crash oder Ressourcenexhaustion der Parser durch Zip-Bomb/Polyglot/korrumpierte OLE-Strukturen. | Verfügbarkeit der Analyse- und Signierungsleistung | Worker fallen aus, Vorgänge stauen, Portal teilweise unbenutzbar. | mittel | Ingestion-Prüfung vor Scanner-Übergabe: Kompressionsverhältnis, Größen-/Strukturplausibilität (REQ-23, AK-23); Größenlimit 25 MB (REQ-10); Engine-Stage-Timeouts. | offen |
| TM-14 | Upload-Flooding und Queue-Überlastung durch parallele Groß-Uploads. | Verfügbarkeit des Portals | Legitime Einreichungen werden blockiert, Backlog wächst unbegrenzt. | mittel | Rate-Limit und Backpressure in der Ingestion; harte Größen- und Parallelitätslimits; horizontale Worker-Skalierung (D8); DLQ statt Blockade (REQ-22). | offen |
| TM-15 | Engine-Crash oder Endlosschleife durch bösartig konstruierte Dateien im Worker. | Verfügbarkeit und Isolation der Scanner | Worker-Prozess stirbt wiederholt, Verarbeitung stoppt. | mittel | Stage-Timeouts mit CancellationToken (AMSI synchron → app-seitige Deadline, R1); Container-Isolation der Worker; Health-Checks; MassTransit-Retry mit DLQ und Vorgangsstatus `Fehler` (REQ-22, AK-22). | umgesetzt |
| TM-16 | Conjur/Vault-Ausfall blockiert die Signierkette. | Verfügbarkeit der Signierung | Signieraufträge stauen oder gehen verloren. | niedrig | Polly Retry (exponentiell + Jitter) + Circuit Breaker (ADR-0002); Queue-Redelivery als persistierender Puffer; Fault-Queue + Alarm nach Retry-Limit (REQ-22). | umgesetzt |
| TM-17 | Einreicher nutzt Review- oder Admin-Funktionen über direkte API-Aufrufe. | Autorisierungsgrenzen | Unbefugte treffen Signier- oder Admin-Entscheidungen. | mittel | RBAC aus IdP-Gruppen-Claims, serverseitige Policy je Endpunkt (REQ-09); `403` bei fehlendem Claim (AK-09); keine rollenbezogenen Entscheidungen clientseitig. | umgesetzt |
| TM-18 | Umgehung der Separation-of-Duties (Einreicher gibt eigene Datei frei). | Integrität des Review-Gates | Verdachtsdateien werden ohne unabhängige Prüfung signiert. | niedrig | Technische SoD-Prüfung in der Saga: `ReviewerId == SubmitterId` wird abgelehnt und erfordert zweiten Bearbeiter (REQ-17, AK-17). | umgesetzt |
| TM-19 | Fremd-Publish von `SignMacroRequested` auf die Sign-Queue. | Signier-Gate | Ungeprüfte Dateien werden signiert. | mittel | Sign-Queue erreichbar nur von der Saga (Netzwerk-Policy im internen Container-Netz); SigningService verifiziert `ContentSha256` und Vorgangsstatus `SignierungAngefragt` vor jeder Signatur. | umgesetzt |
| TM-20 | Betrieb des LocalDev-Key-Providers in einer Produktiv-Umgebung (Konfigurationsfehler). | Signing-Schlüssel | Dev-Key signiert produktiv, Vertrauenskette kollabiert. | niedrig | Startup-Validierung fail-fast: `LocalDevKeyProvider` außerhalb des Dev-Profiles verweigert den Start (REQ-15/24); Konfigurations-Profiling Teil der Deployment-Profile (Anhang E). | umgesetzt |

### 3.3 Akzeptierte Risiken

- **IdP-Kompromittierung** wird dem IdP-Betrieb (MFA, Conditional Access) zugerechnet, nicht diesem Modell. (Epic #7, TM — Annahmen und Abgrenzung)
- **Endpoint-AV auf den Client-Windows-Hosts** ist bewusst kein Bestandteil des Modells; die Semantik `Baseline-Clean ≠ Endpoint-AV-Clean` ist in ADR-0004 dokumentiert. (Epic #7, TM — Annahmen und Abgrenzung)
- **Host-/Infrastruktur-Härtung** (Docker-Host, Windows-Host der optionalen AMSI-Bridge, Netzwerk-Segmentation darunter) ist Betriebsverantwortung und wird nur an den Schnittstellen (IF-10) modelliert. (Epic #7, TM — Annahmen und Abgrenzung)
- **VBA-Stomping** (P-Code/Quelltext-Divergenz) ist ein dokumentierter Blindspot aller quelltextbasierten Scanner (R4); er wird als Restrisiko akzeptiert und im Runbook (§14) als bekannte Limitation geführt. (Epic #7, TM — Annahmen und Abgrenzung)
- **Malware-Inhalte in eingereichten Dateien** werden als gegeben angenommen; das Modell schützt die Plattform und das Key-Material, nicht die Annahme, dass jede Malware erkannt wird. (Epic #7, TM — Annahmen und Abgrenzung)
- **SF-01 (niedrig, akzeptiert):** (API-Key als v1-Authentisierung genügt Betrieb; authn-jwt Betriebs-Backlog; IF-05/OP-06 präzisiert, durch Entwickler) (TM-09 / IF-05)
- **SF-05 (niedrig, akzeptiert):** (IF-06 als fail-closed Betriebs-Backlog präzisiert, durch Entwickler) (IF-06)
- **RV-08 (niedrig, akzeptiert):** (Formatvorgabe implement-ticket §4 hat Vorrang, durch Entwickler) (CONVENTIONS §4)

**BSI/ISO-Bezug:** CON.8.A21 (Bedrohungsmodellierung), CON.8.A22 (Sicherer Software-Entwurf), APP.7.A6, A.8.27 (Secure Architecture)

---

## 4. Architektur & Architektur-Entscheidungen *(Pflicht)*

### 4.1 Übersichtsdiagramm

*Status: Entsteht in der Spezifizierungsphase (C4-Container-Diagramm: AppHost, WebUI, WorkerService, SigningService, PostgreSQL, RabbitMQ).*

### 4.2 Technologie-Stack

- Stack: .NET 8 (ASP.NET Core, EF Core, MassTransit + RabbitMQ, `System.Security.Cryptography.Pkcs.SignedCms`, OpenMcdf, Microsoft.O365.Security.Native.libyara.NET.Core, clamd/ClamAV, CyberArk conjur-api .NET SDK, Keycloak (Dev-IdP), MailPit (Dev-SMTP)). (Epic #7, OP-01)

| Schicht | Technologie | Version | Bemerkung |
|---|---|---|---|
| Frontend | | | |
| Backend | | | |
| Datenbank | | | |
| Komponenten / Bibliotheken | | | |

### 4.3 Architektur-Entscheidungen (ADRs)
| ID | Entscheidung | Kontext | Konsequenz | Datum |
|---|---|---|---|---|
| ADR-01 | IdP-Strategie: Entra ID direkt in Prod, Keycloak nur als Dev-IdP | Das Portal spricht generisches OIDC (Authority/Metadaten per Konfiguration). Lokal läuft Keycloak als Container im Aspire-AppHost mit Realm-Import und Test-Usern; produktiv wird Entra ID direkt angebunden. Ein Keycloak-Broker vor Entra ID wurde abgelehnt: Betriebs-Overhead ohne aktuellen Bedarf, und der OIDC-Contract macht einen späteren Wechsel zur Konfigurationsänderung, nicht zu einem Code-Change. | | 2025-09-27 |
| ADR-02 | Signing-Key: Direct Conjur REST mit JWT-AuthN, Key ausschließlich Memory-only | Der SigningService holt den PKCS#12 per Conjur REST-API direkt aus dem Prozess (kein CP-Agent, kein IIS-CCP) mit `authn-jwt` (Kubernetes: FileJWTProvider auf Service-Account-Token, kein Bootstrap-Geheimnis; Dev: API-Key als Env-Secret). Das Zertifikat wird pro Signing-Vorgang frisch abgerufen als base64-Variable, in `X509Certificate2` mit `EphemeralKeySet` im Arbeitsspeicher gehalten und nach Verwendung verwischt — niemals auf Disk, niemals gecacht. Resiliency: Polly Retry (exponentiell + Jitter) + Circuit Breaker; MassTransit-Redelivery als persistierender Puffer bei Vault-Ausfall; 401-nach-Refresh und 404 sind nicht transient und gehen früh in die Fault-Queue. | | 2025-09-27 |
| ADR-03 | VBA-Signierung: Eigenbau `VbaProjectSigner` (managed .NET), Windows-SIP-Agent als dokumentierter Fallback | Die VBA-Projekt-Signatur wird als eigenständiger, rein managed .NET-Baustein (`VbaProjectSigner`, hinter `IVbaProjectSigner`) implementiert: MS-OVBA-§2.4.2-Normalisierung (V3: `V3ContentNormalizedData || ProjectNormalizedData`, SHA-256), CMS/PKCS#7 via `SignedCms`, CFB-Rewriting via OpenMcdf — einheitlich für .xlsm/.docm/.pptm, lauffähig im Linux-Container, null Lizenzkosten. Begründung: Alle kommerziellen .NET-Libraries (EPPlus, Aspose, GroupDocs) sind Excel-only und lizenzpflichtig; OSS-Libraries, die VBA-Signaturen erzeugen, existieren in keiner Sprache. Die Microsoft-Referenz-Implementierung (signtool + Office-SIPs) ist kostenlos, aber x86-only, Windows-only und benötigt Disk-Materialisierung der Datei — sie widerspräche der Container-Isolation des SigningService. Sie bleibt als Fallback dokumentiert: Scheitert die Normalisierung am Golden-File-Test, wird hinter `IVbaProjectSigner` auf den Windows-Agenten umgeschwenkt (kein Contract-Bruch). | | 2025-09-27 |
| ADR-04 | AMSI als optionaler Engine-Stage, nie als Pflicht | AMSI-Scanning läuft nicht in der Aspire/Linux-Topologie (Aspire supportet keine Windows-Container; MCR-Images enthalten keinen AMSI-Provider). Die `AmsiScanBridge` (.NET-Worker auf Windows-Host, RabbitMQ-angebunden) ist daher ein optionales Deployment-Profil, kein Bestandteil des Standard-Deployments. Standard ist die Linux-Baseline (ClamAV + YARA + Heuristik). Der Message-Contract ist engine-neutral mit Degradation: AMSI-Ausfall/Timeout erzeugt `Inconclusive` und erzwingt Review — niemals `Clean`. Begründung: Endpoint-AV auf den Clients ist eine zweite Kontrollinstanz, aber die Signier-Entscheidung fällt am Gate; Kunden mit höherem Schutzbedarf aktivieren die Bridge explizit. Die Semantik `Baseline-Clean ≠ Endpoint-AV-Clean` ist dokumentationspflichtig. | | 2025-09-27 |

**BSI/ISO-Bezug:** CON.10.A11 (Softwarearchitektur), CON.8.A12 (Ausführliche Dokumentation), A.8.27 (Secure Architecture)

---

## 5. Datenflüsse & Schnittstellen *(Pflicht)*

*Status: Externe und interne Schnittstellen werden featureweise als `IF-nn` im Threat Model erfasst und hier konsolidiert.*

### 5.1 Externe Schnittstellen
| ID | Name | Protokoll | Authentisierung | Daten | Datenfluss | Verantwortlich | Dokumentation |
|---|---|---|---|---|---|---|---|
| IF-01 | WebUI-Upload-Endpunkt (HTTPS) | | OIDC (Entra ID prod / Keycloak dev) | Makro-Datei (.xlsm/.docm/.pptm) + Metadaten | eingehend | | Epic #7 (IF-01) |
| IF-02 | IdP-OIDC (Login, Discovery, UserInfo) | | OIDC-Client (Client-Credentials) | Authentisierung, Gruppen-Claims | ausgehend | | Epic #7 (IF-02) |
| IF-03 | SignalR-Hub (Live-Status, Dashboard) | | OIDC (Cookie/Bearer) | Vorgangsstatus, Benachrichtigungen | eingehend | | Epic #7 (IF-03) |
| IF-04 | Conjur REST-API (Secrets Manager) | | API-Key (v1 implementiert, Dev+Prod) / authn-jwt (K8s-SA-Token) als Betriebs-Backlog (SF-01 akzeptiert), TLS | base64(PKCS#12) kurzlebig abgerufen | ausgehend | | Epic #7 (IF-05) |
| IF-05 | Azure Key Vault (Fallback-Key-Provider) | | Betriebs-Backlog — v1 nicht implementiert (fail-closed, SF-05 akzeptiert); geplant: Managed Identity/Client-Credential, TLS | Zertifikat/P12 | ausgehend | | Epic #7 (IF-06) |
| IF-06 | SMTP (Benachrichtigungen) | | SMTP-Auth je Provider, TLS | Status-E-Mail (Link, keine Inhalte) | ausgehend | | Epic #7 (IF-07) |
| IF-07 | WebUI-REST-Endpunkte (Review-Aktionen, Audit-Lesung, Downloads, Notifications) | | OIDC, zentrale Rollenpolicies (RequireAuthorization: Owner/Editor/Admin pro Endpunkt) — nachträglich ergänzt (SF-06) | Vorgangs-IDs, Review-Entscheidungen, Audit-Einträge, Blob-Bytes | eingehend | | Epic #7 (IF-13) |

- Externe Schnittstellen des Systems: OIDC-Login (IF-01–IF-03) und SMTP (IF-07); alle übrigen Datenflüsse sind intern. (Epic #7, OP-11)

### 5.2 Interne Schnittstellen
| ID | Komponente A | Komponente B | Protokoll | Daten | Bemerkung |
|---|---|---|---|---|---|
| IF-10 | | | | Nachrichten per Anhang A | intern — Epic #7 (IF-04) |
| IF-11 | | | | Persistenzdaten | intern — Epic #7 (IF-08) |
| IF-12 | | | | Datei-Bytes zur AV-Prüfung | intern — Epic #7 (IF-09) |
| IF-13 | | | | `ScanRequested`/`ScanCompleted` per HTTP (Loopback-Client im Worker, ADR-0004) — korrigiert aus „RabbitMQ" (SF-04) | intern — Epic #7 (IF-10) |
| IF-14 | | | | Datei-Bytes, JSON-Befunde | intern — Epic #7 (IF-11) |
| IF-15 | | | | Datei-Binärdaten | intern — Epic #7 (IF-12) |

### 5.3 Datenflussdiagramm

*Status: Entsteht auf Anwendungsebene nach der Spezifizierung.*

**BSI/ISO-Bezug:** APP.7.A3 (Sicherheitsfunktionen zur Systemintegration), APP.3.1.A11 (Schnittstellen), A.5.14 (Information Transfer)

---

## 6. Authentisierung & Autorisierung *(Pflicht)*

*Status: Verfahren (z. B. OIDC/SSO gegen bestehendes Unternehmens-IAM) und Rollenmodell werden in der Spezifizierung festgelegt und hier nachgetragen.*

### 6.1 Authentisierung

- Authentisierung ausschließlich per OIDC — produktiv Entra ID, lokal Keycloak-Container; keine lokalen Konten, MFA am IdP. (Epic #7, OP-02)

### 6.2 Autorisierung / Berechtigungskonzept

- Autorisierung per RBAC aus IdP-Gruppen-Claims (`Einreicher`, `Bearbeiter`, `Admin`); SoD erzwungen: Einreicher kann eigene Vorgänge nicht freigeben. (Epic #7, OP-03)

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
- Rollenvergabe erfolgt ausschließlich durch IdP-Gruppenmitgliedschaft; das Portal vergibt keine Rollen. (Epic #7, OP-04)

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

- Verfahren: SHA-256 (VBA-V3-Contents-Hash, Audit-Hash-Kette), PKCS#7/CMS-SignedCms mit SpcIndirectDataContent (OID 1.3.6.1.4.1.311.2.1.4), TLS 1.2+ für alle externen Verbindungen. (Epic #7, OP-05)

### 8.2 Schlüsselmanagement

- Schlüsselmanagement: Codesigning-P12 in CyberArk Conjur (v1: API-Key-AuthN, base64-Variable), Abruf pro Signing, Memory-only `EphemeralKeySet`, Wipe nach Verwendung, Rotation vault-seitig; authn-jwt (K8s-SA) als Betriebs-Backlog (SF-01); Fallback Azure Key Vault (Backlog, IF-06); Dev: lokales selbstsigniertes Zertifikat (User-Secret, nie im Git). (Epic #7, OP-06)

**BSI/ISO-Bezug:** CON.1 (Kryptokonzept), A.8.24 (Use of Cryptography)

---

## 9. Logging & Monitoring *(Pflicht)*

### 9.1 Log-Quellen und Ereignisse
- Geloggte Ereignisse: Einreichung (Prüfauftrag), Analyseergebnis, Review-Entscheidung, Signierung, Login/Logout, Berechtigungsänderungen, Fehler und Dead-Letter-Queue-Ereignisse.
- Telemetrie: OpenTelemetry über den .NET-Aspire-AppHost; strukturiertes Logging via `ILogger` (keine String-Interpolation in Log-Templates).

### 9.2 Log-Schutz und Aufbewahrung
- Speicherort und -dauer: Operational Logs 90 Tage; audit-relevante Ereignisse (Signierentscheidungen, Berechtigungsänderungen, Logins) 1 Jahr.
- Schutz: keine Secrets und keine Inhalte aus Upload-Dokumenten in Logs — nur Datei-IDs und Hashwerte.
- Audit-Trail append-only mit SHA-256-Hash-Kette, Aufbewahrung 1 Jahr; Prüfung der Kette bei Admin-Abruf. (Epic #7, OP-07)

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

- Upload-Restriktionen: max. 25 MB (konfigurierbar), nur .xlsm/.docm/.pptm, Zip-Bomb-/Polyglot-Prüfung in der Ingestion; E-Mail nur Status + Link. (Epic #7, OP-08)

### 10.3 Hardening-Checkliste

- Hardening: SigningService netzwerk-isoliert (Front-End-Netz ohne Erreichbarkeit), Container non-root, kein Key-Material auf Disk, Sign-Queue nur von der Saga erreichbar, YARA-Regelset versioniert im Image. (Epic #7, OP-09)

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
| 1.2 | 2026-10-01 | Epic #7 (Security-Review-Stand): §3.1 SA-01–15 (REQ-03–24), §3.2 TM-01–20, §3.3 Annahmen/Abgrenzung + akzeptierte Findings (SF-01, SF-05, RV-08), §4.3 ADR-01–04, §5.1 IF-01–07 + §5.2 IF-10–15 (Epic IF-01–13, Security-Review-Rev.), OP-01–12-Festlegungen (§4.2/§5.1/§6/§7.1/§8/§9.2/§10/§14/Anhang A), §13.1 Security-Review-Zeile + §13.2 Findings (SF-01–06, RV-20, RV-22), §1 Metadaten Review-Datum | Patrick Wels | Patrick Wels | Ja |

**BSI/ISO-Bezug:** OPS.1.1.3.A11 (Kontinuierliche Dokumentation), A.8.32 (Change Management)

---

## 13. Audit- und Testhistorie *(Pflicht)*

### 13.1 Durchgeführte Sicherheitsprüfungen
| Datum | Art der Prüfung | Durchgeführt von | Ergebnis | Bemerkung |
|---|---|---|---|---|
| 2025-09-27 | Initiale Dokumenterstellung | Intern | — | Erste Version; Security-Prüfungen (Code-Review, SAST/SCA) folgen mit der Umsetzung |
| 2026-10-01 | Security-Review | Patrick Wels | 6 Findings (0 hoch) | Epic #7 |

### 13.2 Abweichungs- und Maßnahmenverfolgung
| ID | Finding | Risiko | Maßnahme | Frist | Status |
|---|---|---|---|---|---|
| SF-01 | TM-09 / IF-05 — src/OfficeSelfSigningPortal.SigningService/Keys/CyberArkConjurKeyProvider.cs:147-166 (API-Key-Login via `/authn`) | niedrig | Conjur-Authentisierung nur als API-Key-Variante (Dev) implementiert; deklariierte authn-jwt-Variante (K8s-SA-Token, IF-05/OP-06/TM-09) fehlt im Produktivpfad — authn-jwt implementieren oder IF-05/OP-06 auf API-Key präzisieren und akzeptieren | | akzeptiert (API-Key als v1-Authentisierung genügt Betrieb; authn-jwt Betriebs-Backlog; IF-05/OP-06 präzisiert, durch Entwickler) |
| SF-02 | TM-13 (OP-01) — OpenMcdf 2.4.1 in src/OfficeSelfSigningPortal.SigningService/OfficeSelfSigningPortal.SigningService.csproj:21, src/OfficeSelfSigningPortal.WorkerService/OfficeSelfSigningPortal.WorkerService.csproj:29, tests/OfficeSelfSigningPortal.TestSupport/OfficeSelfSigningPortal.TestSupport.csproj:12 (NU1902: GHSA-5qwm-7pvp-w988, GHSA-jxpf-xq2m-q525, moderat) | mittel | Zentrales Upgrade auf OpenMcdf ≥ 3.x (mit RV-14/RV-19 Versionsliste); Parserpfade (Heuristik-Extraktion, VbaProjectSigner) regressionstesten | | offen |
| SF-03 | TM-14 — src/OfficeSelfSigningPortal.WebUI/Program.cs:56-77 (RateLimiter nur Rückfrage-Kanal); src/OfficeSelfSigningPortal.WebUI/Ingestion/SubmissionEndpoints.cs:60-61 (kein Limit am Upload); src/OfficeSelfSigningPortal.WorkerService/Messaging/AnalysisSagaBusConfiguration.cs:78-86 (Scan-Endpoint ohne ConcurrencyLimit/Prefetch) | mittel | Rate-Limit/Backpressure am Upload-Endpunkt (z. B. globale Fixed-Window-Policy) und Parallelitätslimit (ConcurrencyLimit/PrefetchCount) am Scan-Endpoint ergänzen bzw. bewusst als akzeptierte Restriktion dokumentieren | | offen |
| SF-04 | IF-10 — src/OfficeSelfSigningPortal.WorkerService/Scanning/AmsiScanEngine.cs:38-45 (HTTP POST an AmsiBridgeUrl, kein AuthN-Mechanismus) | niedrig | IF-10 deklariert RabbitMQ-Transport (`ScanRequested`/`ScanCompleted`), implementiert ist HTTP ohne Authentisierung — IF-10 auf HTTP korrigieren oder Bridge auf Bus-Vertrag umbauen; Bridge-Endpunkt-AuthN (internes Netz + Shared-Secret/mTLS) festlegen | | behoben (IF-10 auf HTTP korrigiert, Bridge-AuthN mit Backlog F5, durch Entwickler) |
| SF-05 | IF-06 — src/OfficeSelfSigningPortal.SigningService/Keys/AzureKeyVaultKeyProvider.cs:11-20 (`NotSupportedException`) | niedrig | Deklarierter Fallback-Key-Provider ist fail-closed, aber nicht verfügbar — AzureKeyVaultKeyProvider implementieren oder IF-06 als „fail-closed, Betriebs-Backlog" präzisieren und akzeptieren | | akzeptiert (IF-06 als fail-closed Betriebs-Backlog präzisiert, durch Entwickler) |
| SF-06 | IF-01 — src/OfficeSelfSigningPortal.WebUI/Review/ReviewEndpoints.cs, Audit/AuditEndpoints.cs, Download/DownloadEndpoints.cs, Notifications/NotificationEndpoints.cs (neue eingehende REST-APIs ohne eigene IF-Zeile) | niedrig | Vollständigkeit: Review/Audit/Download/Notifications teilen die OIDC-Boundary von IF-01 — IF-01-Beschreibung auf „WebUI-REST (Upload, Review, Audit, Download, Notifications)" erweitern oder eigene IF-Zeilen ergänzen | | behoben (IF-13 für REST-Endpunkte ergänzt, durch Entwickler) |
| RV-20 | TM-04 (Grenze der Gegenmaßnahme) — src/Ossp.Audit/AuditHashChain.cs (Verify) | niedrig | Hash-Kette erkennt Feldmanipulation und Lücken innerhalb eines Vorgangs; die Löschung der neuesten Einträge (Tabellenende) ist ohne Nachfolger-Verweis prinzipiell unsichtbar — inhärente Eigenschaft von Hash-Ketten | | offen |
| RV-22 | REQ-18 / Best-Effort-Grenze — src/OfficeSelfSigningPortal.WebUI/Ingestion/SubmissionService.cs (Audit-Append nach SaveChanges) | niedrig | Upload-Audit liegt außerhalb der Upload-Transaktion und ist best-effort (etabliertes Pattern aus T04): ein Fehlversuch erzeugt eine nicht protokollierte Lücke statt eines Rollbacks | | offen |

**BSI/ISO-Bezug:** APP.3.1.A22 (Penetrationstest und Revision), A.8.29 (Security Testing), A.8.34 (Protection during audit testing)

---

## 14. Betriebshandbuch / Runbook *(Pflicht)*

- Runbook-Einträge: Vault-Ausfall (Circuit Breaker, Fault-Queue, Alarm), AMSI-Bridge-Ausfall im Profil `hardened` (Verdict `Inconclusive` → Review-Pflicht), DLQ-Handling (Vorgangsstatus `Fehler`), Retention (Dateien 90 Tage, Audit 1 Jahr), Conjur-Rotation. (Epic #7, OP-10)

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
# Bridge-Endpunkt UND Shared-Secret betriebsseitig bereitstellen (User-Secret oder
# Umgebungsvariable), sonst verweigert der AppHost-Start. Im Dev-Betrieb startet die
# AmsiScanBridge als zusätzliche AppHost-Ressource auf Loopback; im Produktionsbetrieb
# läuft sie auf einem dedizierten Windows-Host und der WorkerService ruft sie dort ab.
dotnet user-secrets set --project src/OfficeSelfSigningPortal.AppHost "Parameters:amsi-bridge-url"   "https://<windows-host>:<port>"
dotnet user-secrets set --project src/OfficeSelfSigningPortal.AppHost "Parameters:amsi-bridge-token" "<mindestens 32 zufällige Bytes, base64 oder hex>"
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
  Authentisierungs-Fehler (HTTP 401) zählen betrieblich als Ausfall: falsches oder rotiertes
  `AmsiScanBridge:Token` → Brücke antwortet 401 → AMSI-Stage `Failed` → Inconclusive.
- Erkennen: `Failed`-Eintrag der AMSI-Stage im Scan-Ergebnis (`Bridge-HTTP 401` oder
  `Bridge-HTTP 5xx`); gehäufte Vorgänge in `ReviewAusstehend`; Health-Endpoint
  `GET /health` der Brücke antwortet 200 (Loopback-Probe).
- Handlung: Bridge-Dienst auf dem Windows-Host prüfen/neustarten; bei Token-Drift den
  Parameter `Parameters:amsi-bridge-token` aktualisieren (AppHost + WorkerService erhalten
  denselben Wert). Bestehende Vorgänge in `ReviewAusstehend` manuell durch den Bearbeiter
  entscheiden (Freigabe erzeugt keinen neuen Scan — die Entscheidung dokumentiert den
  AMSI-Ausfall).

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

- Regelpflege: kuratiertes YARA-Subset (Neo23x0/signature-base) mit `scoreVersion`-Pflege und Konfigurations-Mapping Regelname→Score; periodische Scoring-Kalibrierung am eigenen Korpus (Backlog). (Epic #7, OP-12)

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
