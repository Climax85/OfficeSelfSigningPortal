# Artefakt-Erweiterung für `to-spec` / `to-tickets`

> Delta-Spezifikation (verbindlich, siehe [secure-sdlc-konventionen.md](secure-sdlc-konventionen.md) §1). **Mechanismus:** Artefakt-Pass. **Gilt für:** Local-Markdown-Tracker (`.scratch/<feature>/`). Die SKILL.md-Dateien von `to-spec`/`to-tickets` bleiben unverändert — diese Datei ist der einzige Eingriffspunkt.

## 1. Mechanismus: Artefakt-Pass

Die Erweiterung ist **kein Fork und kein Modus-Flag**, sondern ein Artefakt-Pass: ein Post-Schritt, der **nach** dem unveränderten Pocock-Skill läuft und dessen Tracker-Ausgabe (Spec, Tickets) in Contract-Artefakte übersetzt.

- **Kein Fork:** die Pocock-Skill-Texte werden nicht kopiert oder editiert.
- **Kein Modus-Flag:** ein Flag, das der Skill-Text nicht kennt, ist für ein schwaches Modell ein toter String. Stattdessen aktiviert der Aufrufer den Pass explizit als eigenen Schritt.
- **Selbsttragend:** der Pass liest nur die veröffentlichten Tracker-Dateien und die Templates — der Pocock-Skill-Text ist keine Eingabe.

**Aktivierung:** nach Abschluss des Pocock-Skills fordert der Aufrufer (Entwickler:in oder `secure-feature`) den Pass an und nennt das Feature-Verzeichnis `.scratch/<feature>/` und das Profil (`klein`/`groß`, Default `klein`).

## 2. Vorbedingungen (harte Stop-Stellen)

| # | Prüfung | Bei Verletzung |
|---|---|---|
| V1 | Feature-Verzeichnis mit `spec.md` existiert | Stop: „Artefakt-Modus braucht eine veröffentlichte Spec — erst `to-spec` ausführen." |
| V2 | Templates auflösbar: Pfade aus `STATUS.md` § Pfade, sonst `templates/` im Repo-Root | Stop mit Meldung, welche Template-Datei fehlt |
| V3 | Pass B: `anforderungen.md` existiert im Feature-Verzeichnis | Stop: „Erst Pass A ausführen — REQ→AK-Abdeckung sonst nicht prüfbar." |
| V4 | `STATUS.md` vorhanden → Profil daraus überschreibt den Aufrufer-Wert | (kein Stop, Profil aus STATUS.md ist verbindlich) |

## 3. Pass A — nach `to-spec`

Übersetzt die Spec in bis zu drei Artefakte. Sektions-Mapping:

| Spec-Sektion | Artefakt | Tabelle |
|---|---|---|
| `User Stories` | `use-cases.md` | UC-Tabelle — **nur Profil `groß`** |
| `Problem Statement`, `Solution` | `anforderungen.md` | Fachliche Anforderungen |
| `Implementation Decisions` | `anforderungen.md` | Funktionale Anforderungen |
| `Testing Decisions`, `Out of Scope`, `Further Notes` | — | keine Artefakte |

**Ablauf:**

0. **Abgleich (Reconcile) zuerst:** das Artefakt kann aus Spezifizieren bereits gefüllt sein (Regel §5.1: erster Schreiber). Jede spec-abgeleitete Zeile wird gegen den vorhandenen Tabelleninhalt abgeglichen: deckt eine vorhandene Zeile (gleiche Anforderung, auch anders formuliert) den Eintrag ab, wird **keine neue Zeile angelegt** — der Write-back (Schritt 4) vergibt die vorhandene ID. Nur fachlich neue Inhalte minten eine ID ab max+1. Nie duplizieren, nie überschreiben.

1. `use-cases.md` füllen (nur `groß`): jede nummerierte User Story → genau eine UC-Zeile, in Story-Reihefolge. Name = zwei–drei Wörter aus dem „I want"-Teil; Akteur aus „As an"; Auslöser und Ergebnis je ein Satz. **Ausnahme (Abgleich):** deckt eine vorhandene UC-Zeile die Story ab (gleicher Akteur und Ergebnis), erhält die Story die vorhandene ID im Write-back und es entsteht keine neue Zeile.
2. Fachliche REQ: je Satz aus `Problem Statement`/`Solution`, der eine Eigenschaft des Systems fordert, eine Zeile. Quelle = `Spec`.
3. Funktionale REQ: je Eintrag in `Implementation Decisions` eine Zeile, als ein Satz formuliert. Security-Flag = `ja`, wenn die Verletzung der Anforderung ein Sicherheitsproblem wäre (Authentisierung, Autorisierung, Validierung, Geheimnisse, Datenflüsse nach außen), sonst `nein`. Quelle = `UC-nn`, wenn eine Story die Anforderung trägt, sonst `Spec`.
4. IDs minten (§5) und **Write-back** in die Spec: jeder übernommene Satz/Eintrag erhält am Ende seine ID — `(UC-nn)` bzw. `(REQ-nn)`.
5. `STATUS.md` (falls vorhanden): Artefakt-Status der geschriebenen Artefakte auf `fertig`, „Letzte Aktualisierung" = `to-spec Artefakt-Pass`.

**DoD:**

- [ ] Jede nummerierte User Story hat genau eine UC-Zeile (Profil `groß`).
- [ ] Jeder Eintrag in `Implementation Decisions` hat genau eine REQ-Zeile.
- [ ] Jede REQ-Zeile: genau ein Satz, Security-Flag gesetzt, Quelle gesetzt.
- [ ] Jeder übernommene Spec-Satz trägt seine ID inline.
- [ ] Überschriften und Spalten exakt wie im Template.

## 4. Pass B — nach `to-tickets`

Schreibt `akzeptanzkriterien.md` aus den veröffentlichten Ticket-Dateien. Akzeptanzkriterien leiten sich von Ticket-Kriterien ab, nicht von der Spec — Pass A schreibt keine AK.

**Ablauf:**

1. Alle `issues/NN-*.md` in Nummernreihenfolge lesen. Jede Zeile unter `Acceptance criteria` wird ein AK-Eintrag: Kriterium = Zeilentext ohne Checkbox, Art = `security`, wenn das Kriterium eine Security-REQ prüft oder Schutzverletzung thematisiert, sonst `fachlich`, Referenz = `Ticket NN` (plus `REQ-nn`, falls die Zeile eine nennt).
2. REQ-Abdeckung prüfen: jede `REQ-nn` aus `anforderungen.md` braucht mindestens ein AK. Fehlende anfügen, Form „Wenn `<Bedingung aus REQ>`, dann `<erwartetes Verhalten>`", Art gemäß Security-Flag der REQ, Referenz = die `REQ-nn`.
3. IDs minten (§5) und **Write-back** in die Tickets: jede Kriterienzeile in `issues/NN-*.md` erhält das Präfix `(AK-nn)`.
4. `STATUS.md` (falls vorhanden): Artefakt-Status `Akzeptanzkriterien` = `fertig`, „Letzte Aktualisierung" = `to-tickets Artefakt-Pass`.

**DoD:**

- [ ] Jede Kriterienzeile jedes Tickets hat genau eine AK-Zeile und trägt die `AK-nn` im Ticket.
- [ ] Jede `REQ-nn` ist von mindestens einem AK abgedeckt.
- [ ] Jede Security-REQ hat mindestens ein AK mit Art `security`.
- [ ] Überschriften und Spalten exakt wie im Template.

## 5. ID-Konsistenz-Regel (verbindlich)

1. **Ein Mal vergeben:** IDs vergibt der **erste Schreiber** des Artefakts — in der Spezifizierungs-Phase `secure-feature` (nach Grilling), in Umsetzung der Artefakt-Pass für spec-/ticket-abgeleitete Zusätze. Danach unveränderlich — kein Neudruck, kein Umbenennen, keine Lücken schließen.
2. **Ein Zähler je Präfix:** `UC-nn`, `AK-nn` und `REQ-nn` — die REQ-Nummer läuft **fortlaufend über fachliche und funktionale Tabelle** (eine Nummerierung, zwei Tabellen).
3. **Weiterzählen statt überschreiben:** existiert das Artefakt bereits, startet die Nummerierung bei der höchsten vorhandenen ID + 1. Der Pass liest die Tabelle vor der Vergabe.
4. **Verbatim-Referenz:** Referenzen auf Anforderungen, Use-Cases und Kriterien erfolgen immer als ID (`REQ-05`), nie als Freitext.
5. **Write-back in beide Richtungen:** Spec-Sätze und Ticket-Kriterien tragen ihre ID inline (Regeln in §3/§4); Artefakt-Zeilen verweisen zurück über die Quelle-/Referenz-Spalte (`Spec`, `Ticket NN`, `UC-nn`, `REQ-nn`).

## 6. Profil

- `klein` (Default): Pässe schreiben `anforderungen.md` und `akzeptanzkriterien.md`. Kein `use-cases.md` — im Profil `klein` existiert dieses Artefakt nicht.
- `groß`: zusätzlich `use-cases.md`.
- Fehlt die Profil-Angabe beim Aufruf, gilt `klein`. Ein vorhandenes `STATUS.md` ist verbindlich (V4).
