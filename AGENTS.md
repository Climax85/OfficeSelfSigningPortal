# OfficeSelfSigningPortal — Agent-Konventionen

## Agent skills

### Issue tracker

Issues and specs for this repo live as GitHub issues (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, each mapped to the identical label string (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Secure-SDLC

Verbindliche Konventionen des Secure-SDLC-Workflows (Artefakt-Contracts, Kontextbudget-Gesetz, Planungsprofile `klein`/`groß`, `.scratch`-Lebenszyklus, Zustandsführung, Anwendungsdoku, Threat-Model-Ansatz, Reviews): siehe [docs/agents/secure-sdlc-konventionen.md](docs/agents/secure-sdlc-konventionen.md).

Delta-Spezifikation des Artefakt-Passes für `to-spec`/`to-tickets` (ID-Konsistenz, Pass A/B, Write-back): siehe [docs/agents/artefakt-erweiterung-to-spec-to-tickets.md](docs/agents/artefakt-erweiterung-to-spec-to-tickets.md).

App-Dokumentation: `docs/anwendungsdokumentation.md` (Default-Pfad; eine abweichende Konfiguration gehört in diesen Abschnitt, `secure-feature` und `merge-app-docs` lesen sie von hier).
