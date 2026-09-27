# Secure-SDLC-Konventionen

Verbindliche Arbeitsgrundlage für das Secure-SDLC-Skill-Set dieses Repos. Jeder Secure-SDLC-Skill muss mit diesem Dokument und den hier referenzierten Templates arbeiten; er darf die Charting-History nicht kennen müssen.

Gilt für: `secure-feature`, `threat-model`, `security-review`, `merge-app-docs`, `init-app-docs` sowie `review-ticket` und die Artefakt-Erweiterung von `to-spec`/`to-tickets`.

## 1. Hybrid-Grundsatz

- Pococks Skills (`wayfinder`, `grilling`, `to-spec`, `to-tickets`, `implement`, `tdd`, `code-review`, …) bleiben das Fundament. Sie werden nicht umgeschrieben; **dokumentierte Mini-Erweiterungen mit Entwickler-Entscheidung** sind erlaubt (aktuell: Self-Check + Review-Delegation in `implement-ticket`).
- Neue Skills entstehen für: Sicherheit (Threat Model, Security-Review), Artefakt-Orchestrierung, Anwendungsdokumentation, **Qualitätssicherung** (z. B. `review-ticket` als Loop-Partner von `implement-ticket`).
- Eingriff in Pocock-Skills ist genau einer: optionale Artefakt-Ausgaben für `to-spec`/`to-tickets` als Artefakt-Pass (Delta-Spezifikation: [artefakt-erweiterung-to-spec-to-tickets.md](artefakt-erweiterung-to-spec-to-tickets.md), kein Fork).

## 2. Kontextbudget-Gesetz

- Zielmodelle: 128K/256K on-prem, ggf. fähigkeitsschwach. Design-Prämisse: ein Agent mit **leerem Chat-Kontext** muss jede Phase ausführen können.
- Jeder Skill liest **nur** seine Eingabe-Artefakte (per Contract, §4), niemals "das Repo" oder fremde Scratch-Artefakte.
- Jeder Skill schreibt **nur** sein Ausgabe-Artefakt im Template-Format.
- SKILL.md eines Skills inkl. aller Grilling-Anteile: Richtwert ~6.000 Tokens, harte Obergrenze ~8.000.
- Jeder Skill trägt eine harte **Definition-of-Done-Checkliste** (adressiert Ermessensschwäche).

## 3. Zwei Planungsprofile

| | **klein** (grilling-Niveau) | **groß** (wayfinder-Niveau) |
|---|---|---|
| Auslöser | Bugfix, kleine Erweiterung, enge Freitextbeschreibung | Neues Feature mit Schnittstellen/Daten, neue Anwendung, unklarer Umfang |
| Abuse-Cases | ✅ | ✅ |
| Anforderungen (fachlich + funktional) | ✅ | ✅ |
| Akzeptanzkriterien inkl. Security | ✅ | ✅ |
| Threat Model | ✅ (eine STRIDE-Tabelle, Abschnitt) | ✅ (eigenes Artefakt, voll) |
| Use-Cases | ❌ | ✅ |
| Test-Cases inkl. Edge-Cases | ✅ | ✅ |
| ADRs | ❌ | ✅ |
| CONTEXT.md-Update | ✅ immer | ✅ immer |

- Die Profil-Auswahlregel (anhand Feature-Eingang) definiert der Orchestrator-Skill.
- Beim Profil `groß` führt `wayfinder` die Planung: Map mit Decision-Tickets auf dem konfigurierten Tracker, Fog-of-War, ein Ticket pro Session. Die **Security-Frontier ist Pflichtbestandteil jeder Map**: Abuse-Cases, Assets/Trust Boundaries, Security-REQs (Flag) und security-relevante Akzeptanzkriterien müssen als Tickets, Fog-Abschläge aus „Not yet specified" oder Resolutionen abgedeckt sein — Vorschlag durch den Agenten, Bestätigung durch den Entwickler (§8: nichts wird leer erfragt). Die Map ersetzt keine Artefakte; sie füttert sie (Reconcile: erster Schreiber, siehe `artefakt-erweiterung-to-spec-to-tickets.md` §3 Schritt 0).
- `wayfinder` fehlt im Ziel-Repo → Fallback: breadth-first-Grilling-Runden mit derselben Pflicht-Security-Frontier (`secure-feature` §4).
- CONTEXT.md wird über Pococks `/grilling` gepflegt, nicht über eigene Artefakte.

### Detailgrade für das Profil klein (harte Grenzen)

Detailgrad richtet sich an Angriffsfläche und Entscheidungsrelevanz, nicht an Template-Spalten. Grenzen für das Profil `klein`:

| Artefakt | Grenze | Regel |
|---|---|---|
| Abuse-Cases | 2–4 pro Feature | nur für Security-REQs und neue Schnittstellen |
| Threat-Model-Tabelle | 3–8 Zeilen | STRIDE vollständig durchgehen, aber nur realistische Bedrohungen zeilenweise eintragen; Risiko `niedrig` = 1 Zeile, Status `akzeptiert` |
| Neue Schnittstellen (`IF-nn`) | keine Begrenzung | der eine Abschnitt, der nicht schrumpft — er füttert die Anwendungsdoku |
| Akzeptanzkriterien | Security-REQs vollständig, fachlich nur Kernkriterien | Freitext-Eingang ersetzt bei kleinen Features den Rest |
| Test-Cases | AC-Abdeckung zuerst, Rest frei | die Mapping-Spalte `AC-nn → TC-nn` ist die einzige nicht verhandelbare Test-Anforderung |

- Zeitbudget: 30–60 Minuten menschliche HITL-Zeit pro kleinem Feature. Mehr nötig = falsch profiliert, nicht zu ausführlich analysiert.
- Wiederverwendung: etablierte Abuse-Case-Klassiker (z. B. aus der Anwendungsdoku) werden referenziert, nicht neu erfunden.

## 4. Artefakt-Contracts

Artefakte sind Markdown-Dateien in `.scratch/<feature>/`, strikt im Template-Format. Templates sind **Contracts, keine Dokumente**: stabile IDs, eindeutige Pflichtabschnitte, knapp.

### Sprachregel (Skills englisch, Artefakte deutsch)

- SKILL.md-Dateien des Skill-Sets sind englisch.
- Artefakte — Templates und alle Instanzen in `.scratch/<feature>/` — werden vollständig auf Deutsch befüllt, Überschriften exakt aus dem Template übernommen.
- Contract-Werte (Abschnittsnamen wie „Pfade", „Offene Entscheidungen", „Neue Schnittstellen/Datenflüsse", Phasen-Enum, Statuswerte wie `offen / entwurf / fertig`) bleiben deutsch und werden in englischen SKILL.md-Dateien **verbatim zitiert — nie übersetzt oder paraphrasiert**. Die deutsche Zeichenkette im Template ist der Contract.
- Es gibt keinen Übersetzungsschritt im Workflow: Ein Skill erzeugt ein Artefakt, indem er das deutsche Template im Format befüllt.

### Template-Standort

- Zentrale Template-Quelle: `templates/` im Repo (wird mit Ticket 02 erstellt).
- Der Orchestrator materialisiert beim Anlegen eines Features die **aufgelösten absoluten Pfade aller Templates und Artefakte im `STATUS.md`**. Andere Skills lesen Pfade ausschließlich von dort und lösen nie selbst auf.

### Artefaktliste (final)

| Artefakt | Datei | ID-Schema |
|---|---|---|
| Use-Cases | `use-cases.md` | `UC-nn` |
| Abuse-Cases (narrativ) | `abuse-cases.md` | `AC-nn` |
| Anforderungen (fachlich + funktional) | `anforderungen.md` | `REQ-nn` |
| Akzeptanzkriterien inkl. Security | `akzeptanzkriterien.md` | `AK-nn` |
| Threat Model (STRIDE + Schnittstellen-Delta) | `threat-model.md` | `TM-nn`, `IF-nn` |
| Test-Cases inkl. Edge-Cases | `test-cases.md` | `TC-nn` |
| Zustandsfile | `STATUS.md` | — |
| Ticket-Rückschreiben | `ticket-update.md` | — |
| Review-Findings | `findings.md` | `SF-nn` |

ID-Konsistenz: IDs sind feature-lokal und bleiben über Spec, Artefakte, Tickets und Reviews identisch. Wer eine Anforderung referenziert, nutzt `REQ-nn`, kein Freitext.

### Pflichtabschnitte (Auszug, Detail in den Templates)

- **Threat Model**: STRIDE-Tabelle (Bedrohung, Asset, Auswirkung, Risiko, Gegenmaßnahme, Status) **plus** Pflichtabschnitt „Neue Schnittstellen/Datenflüsse" — der Agent *schlägt* Einträge aus dem Anforderungs-/Grilling-Kontext vor (`IF-nn`), der Entwickler bestätigt oder korrigiert. Nichts wird leer erfragt.
- **Test-Cases**: Spalte „Abdeckt Abuse-Case" — jeder `AC-nn` braucht mindestens einen `TC-nn`. Kein Test ohne dieses Mapping.
- **Akzeptanzkriterien**: Security-Kriterien sind Pflichtbestandteil, keine Zusatzsektion.

## 5. `.scratch`-Lebenszyklus und Audit-Trail

- `.scratch/` ist **gitignored und flüchtig**.
- Audit-Trail stattdessen: Ticket-Referenz ↔ Changelog der Anwendungsdoku (§7). Jedes Feature ist über sein Ticket nachvollziehbar.
- Nach Merge (`merge-app-docs`) und Ticket-Rückschreiben darf der Feature-Ordner gelöscht werden.
- Rückschreiben ins Ticket: **verdichtet** per Template (Kerntabellen, keine Volltexte). Die Ticketbeschreibung ist kein Artefakt-Archiv.

## 6. Zustandsführung

- `.scratch/<feature>/STATUS.md` ist der maschinenlesbare Ersatz für Konversationskontext: aktuelle Phase, fertige Artefakte mit Pfaden, offene Entscheidungen, Ticket-Referenz, Profil (klein/groß).
- Jede Phase aktualisiert STATUS.md als letzten Schritt (Teil der DoD-Checkliste).
- Feature-Eingang: Freitext **oder** Ticket-Referenz über den konfigurierten Tracker-Adapter. Bei Ticket-Referenz gilt die Ticketnummer als Feature-Name; der Adapter ist konfigurierbar, Referenz-Implementierung ist Local-Markdown (siehe `issue-tracker.md`).

## 7. Anwendungsdokumentation

- Ort: `docs/anwendungsdokumentation.md` im Anwendungs-Repo (Pfad konfigurierbar via AGENTS.md, sonst Default); Struktur nach der Vorlage in `docs/anwendungsdokumentation.md` dieses Repos inkl. BSI/ISO-Mapping.
- Kontext-Pfade sind **nicht** konfigurierbar: `CONTEXT.md` und `docs/adr/` liegen per Contract an der Wurzel des Anwendungs-Repos (`merge-app-docs` ADR-Leg und `domain-modeling` lösen sie selbst auf). Wer die Anwendungsdoku in einem Unterverzeichnis führt, legt Kontext und ADRs trotzdem an der Repo-Wurzel an.
- Dazu schlanke `README.md`, die auf die ausführliche Doku verweist.
- Merge = **strukturiert-append**: Threat Models → §3.2, Security-Anforderungen → §3.1, Schnittstellen → §5, ADRs → §4.3, Review-Findings → §13. Kein freies Umschreiben bestehender Sektionen; Widersprüche werden dem Entwickler mit beiden Varianten vorgelegt.
- Jeder Merge: Changelog-Eintrag (§12) mit Ticket-Referenz, Versions-Bump bei sicherheitsrelevanten Änderungen.
- Fehlt die Anwendungsdoku, bricht der Workflow mit einem präzisen Hinweis auf `init-app-docs` ab.

## 8. Threat-Model-Ansatz

- Feature-Ebene: leichtgewichtiges STRIDE (kein PASTA, kein DFD pro Feature). DFD gibt es nur auf Anwendungsebene in der Anwendungsdoku.
- Abuse-Cases sind **narrativ** und vom Threat Model (tabellarisch) getrennt — zwei Artefakte, zwei Sprachen.
- Eskalation: Risiko „hoch" ohne Gegenmaßnahme ist eine harte Stop-Stelle; kein Weitermachen ohne Entwickler-Entscheidung.
- Jede vom Feature neu eingeführte Schnittstelle muss ins Anwendungs-Threat-Model nachgemeldet werden (Pflichtabschnitt, §4).

## 9. Reviews

- `code-review` (Pocock, unverändert): Standards- und Spec-Achse.
- `security-review` (neu): Security-Achse, läuft danach. Prüft Gegenmaßnahmen-aus-Threat-Model gegen Code, Abuse-Case-Abdeckung durch Tests, Authentisierung/Validierung neuer Schnittstellen.
- Findings (`SF-nn`): Referenz (`TM-nn`/`AC-nn`/`IF-nn`/`AK-nn`), Fundstelle, Risiko, Empfehlung → voll in `findings.md`, verdichtet ins Ticket (per `ticket-update.md`), bei Merge in Anwendungsdoku §13.
