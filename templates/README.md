# Artefakt-Templates

Contracts für den Secure-SDLC-Workflow — keine Dokumentvorlagen. Regeln, die für alle Dateien in diesem Verzeichnis gelten:

- **Abschnittsüberschriften und Tabellenspalten exakt beibehalten** — weder ergänzen noch umbenennen noch umsortieren.
- **Beispielzeilen** (z. B. `REQ-01`) durch echte Einträge ersetzen; IDs fortlaufend nummerieren (`REQ-01`, `REQ-02`, …).
- **IDs sind feature-lokal** und bleiben über Spec, Artefakte, Tickets und Reviews identisch. Referenzen immer als ID (`REQ-nn`), nie als Freitext.
- **Profile:** Abschnitte markiert `[nur groß]` entfallen im Profil `klein`. `use-cases.md` existiert nur im Profil `groß`. Das aktive Profil steht im `STATUS.md`.
- **Stop-Regeln** in den Templates (z. B. Risiko hoch ohne Gegenmaßnahme) sind harte Stop-Stellen: der Workflow bricht ab, bis ein Mensch entschieden hat.

| Template | Artefakt-Datei (in `.scratch/<feature>/`) | Schreibt | Liest |
|---|---|---|---|
| [STATUS.md](STATUS.md) | `STATUS.md` | jeder Skill (letzter DoD-Schritt) | jeder Skill (erster Schritt) |
| [use-cases.md](use-cases.md) | `use-cases.md` | `secure-feature`, Artefakt-Pass | `threat-model` |
| [abuse-cases.md](abuse-cases.md) | `abuse-cases.md` | `secure-feature` (mit Entwickler:in) | `threat-model`, `security-review` |
| [anforderungen.md](anforderungen.md) | `anforderungen.md` | `secure-feature`, Artefakt-Pass | `threat-model`, `tdd` |
| [akzeptanzkriterien.md](akzeptanzkriterien.md) | `akzeptanzkriterien.md` | `secure-feature`, Artefakt-Pass | `tdd`, `security-review` |
| [threat-model.md](threat-model.md) | `threat-model.md` | `threat-model` | `security-review`, Entwickler:in |
| [test-cases.md](test-cases.md) | `test-cases.md` | `secure-feature` | `tdd`, `security-review` |
| [ticket-update.md](ticket-update.md) | `ticket-update.md` | `secure-feature`, `security-review`, `merge-app-docs` | Mensch (fügt es ins Ticket ein) |
| [findings.md](findings.md) | `findings.md` | `security-review` | `merge-app-docs`, Entwickler:in |
| [README-app.md](README-app.md) | `README.md` (Wurzel des Anwendungs-Repos) | `init-app-docs` | Menschen im Repo |

Instantiierung: der Orchestrator (`secure-feature`) kopiert die Templates nach `.scratch/<feature>/` und trägt dort und im `STATUS.md` die aufgelösten absoluten Pfade ein. Andere Skills lösen Pfade nie selbst auf.

Artefakt-Pass: `to-spec`/`to-tickets` schreiben dieselben Artefakte ohne Orchestrator über die Delta-Spezifikation [docs/agents/artefakt-erweiterung-to-spec-to-tickets.md](../../../docs/agents/artefakt-erweiterung-to-spec-to-tickets.md) (Pass A: `use-cases.md`, `anforderungen.md`; Pass B: `akzeptanzkriterien.md`).
