# Ticket-Update — <Ticket-Referenz>

> Contract, kein Dokument. **Wer schreibt:** `secure-feature` (pro abgeschlossener Phase), `security-review` (Findings-Tabelle nach dem Security-Review) und `merge-app-docs` (nach Merge). **Wer liest:** Mensch — fügt den Inhalt ins Ticket ein. **Regel:** verdichtet — Kerntabellen, keine Volltexte. Die Ticketbeschreibung ist kein Artefakt-Archiv.

## Zusammenfassung

`<1–2 Sätze: was wurde entschieden und gebaut>`

## Akzeptanzkriterien-Status

| AK-nn | Status |
|---|---|
| AK-01 | `erfüllt / offen / verworfen` |

## Test-Ergebnis

| TC-nn | Ergebnis |
|---|---|
| TC-01 | `bestanden / fehlgeschlagen` |

## Security-Relevantes

| TM-nn | Risiko | Status |
|---|---|---|
| TM-01 | `hoch / mittel / niedrig` | `behoben / akzeptiert (<Begründung, durch wen>) / offen` |

Neue Schnittstellen: `<IF-nn, Status: bestätigt/korrigiert — ein Satz>` (keine = Zeile löschen)

## Findings (Security-Review)

| SF-nn | Referenz | Fundstelle | Risiko | Empfehlung | Status |
|---|---|---|---|---|---|
| SF-01 | `<TM-nn / AC-nn / IF-nn / AK-nn>` | `<Datei:Zeile>` | `hoch / mittel / niedrig` | `<eine Zeile>` | `offen / behoben / akzeptiert (<Begründung, durch wen>)` |

(keine = Satz „Keine Findings." statt Tabelle)

## Doku & Audit-Trail

- Anwendungsdoku: `<Pfad>`, Changelog §12, Version `<x.y>`
