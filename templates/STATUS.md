# STATUS — <Feature-Name>

> Contract, kein Dokument. **Wer schreibt:** jeder Skill (als letzter Schritt seiner DoD-Checkliste). **Wer liest:** jeder Skill (vor jeder anderen Aktion). **Wann:** bei jedem Phasenwechsel. Pflichtabschnitte exakt beibehalten.

## Steuerung

| Feld | Wert |
|---|---|
| Feature | `<Feature-Name oder Ticketnummer>` |
| Ticket | `<Tracker-Referenz>` |
| Profil | `klein / groß` |
| Phase | `Spezifizieren / Threat-Model / Testfälle / Umsetzung / Security-Review / Gemergt` |

## Pfade

Ausschließliche Pfadquelle für alle Skills — vom Orchestrator materialisiert, nie selbst auflösen.

| Artefakt | Template | Instanz (.scratch/<feature>/) |
|---|---|---|
| Use-Cases | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Abuse-Cases | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Anforderungen | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Akzeptanzkriterien | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Threat Model | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Test-Cases | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Ticket-Update | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Findings | `<absoluter Pfad>` | `<absoluter Pfad>` |
| Anwendungsdoku | — | `<absoluter Pfad>` |

## Artefakt-Status

| Artefakt | Status | Anmerkung |
|---|---|---|
| Use-Cases | `offen / entwurf / fertig` | |
| Abuse-Cases | `offen / entwurf / fertig` | |
| Anforderungen | `offen / entwurf / fertig` | |
| Akzeptanzkriterien | `offen / entwurf / fertig` | |
| Threat Model | `offen / entwurf / fertig` | |
| Test-Cases | `offen / entwurf / fertig` | |
| Ticket-Update | `offen / fertig` | |
| Findings | `offen / fertig` | |

## Offene Entscheidungen

- `<Entscheidung, die ein Mensch treffen muss — kein Skill entscheidet stellvertretend>`

(keine offenen Entscheidungen = diesen Abschnitt leer lassen, Überschrift stehen lassen)

## Letzte Aktualisierung

`<YYYY-MM-DD, ausführender Skill>`
