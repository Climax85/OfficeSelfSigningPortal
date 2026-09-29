# Feature-Operations (Secure-SDLC)

Verbindlicher Vertrag für **Feature-Epic** und **Arbeitstickets** auf dem konfigurierten Tracker. Nutzen ihn `secure-feature`, `to-tickets`, `implement-ticket`, `review-ticket` und der Artefakt-Pass (`artefakt-erweiterung-to-spec-to-tickets.md`).

**Zuständigkeiten:** `docs/agents/issue-tracker.md` (Pocock, unverändert) regelt Tracker-Wahl, die CLI-Grundlagen (`gh`/`glab`-Kommandos, Lesen/Schreiben von Issues) und die Wayfinding-Operationen. **Diese Datei** regelt nur das Feature-Epic und seine Kind-Tickets. Phasen-Artefakte (Spec, Threat-Model, …) bleiben lokal unter `.scratch/<feature>/` (gitignored, flüchtig); Epic und Tickets sind der dauerhafte Audit-Anker (siehe `secure-sdlc-konventionen.md` §5).

## Grundregeln (alle Tracker)

- Ein Feature = ein Epic; die Arbeitstickets sind seine Kinder.
- **Epic** wird nach Spezifizieren angelegt und nach Threat-Model / Security-Review verdichtet nachgepflegt. Intake per Ticket-Referenz → die referenzierte Ticket **ist** das Epic: in-place pflegen, niemals ein zweites anlegen.
- **Arbeitstickets** in Abhängigkeitsreihenfolge anlegen (Blocker zuerst), damit Blocking-Kanten echte Referenzen tragen.
- **Claim** erfolgt vor jeder Arbeit und ist exklusiv (Assignee bzw. `Status: claimed`). Ein Ticket pro Session.
- **Frontier** = offen, unblocked, unclaimed; Abhängigkeitsreihenfolge (lokal: niedrigste Nummer) entscheidet.
- **Kommentare** fassen zusammen: was gebaut wurde, Testzahlen, Commit-Hashes, Review-Verdikt, PR-/MR-Referenz (GitHub/GitLab).

## Epic-Body (alle Tracker, deutsch, verdichtet)

```markdown
## Ziel
<Intake in 2–3 Sätzen>

## Ergebnisse Spezifizieren
<Abuse-Cases verdichtet; REQ/AK-Kern als Counts plus die security-geflaggten per ID; offene Entscheidungen>

## Verweise
<Artefakt-Verzeichnis `.scratch/<feature>/` (flüchtig); Wayfinder-Map (Profil groß); App-Docs-Pfad>
```

## Local Markdown

Referenz-Implementierung: Dateien im Feature-Verzeichnis (CLI-Grundlagen: `issue-tracker.md`).

- **Epic**: `.scratch/<feature>/epic.md` (Feature-Name = Verzeichnisname), Body wie oben.
- **Arbeitsticket**: eine Datei pro Ticket, `.scratch/<feature>/issues/<NN>-<slug>.md`, nummeriert ab `01`, Template per `to-tickets`.
- **Blocking**: Zeile `Blocked by: NN, NN` am Dateikopf; unblocked, wenn alle genannten Tickets `resolved`.
- **Frontier-Query**: `issues/` scannen nach offen, unblocked, unclaimed; niedrigste Nummer zuerst.
- **Claim**: `Status: claimed` setzen und speichern — vor jeder Arbeit, die erste Schreiboperation der Session.
- **Status**: `Status:`-Zeile am Dateikopf mit `ready-for-agent` / `claimed` / `resolved` (Rolle-Strings per `triage-labels.md`).
- **Kommentar**: unten unter `## Comments` anfügen.
- **Resolve**: `## Comments`-Eintrag (gebaut, Testzahlen, Commit-Hashes, Review-Verdikt), dann `Status: resolved`, speichern.

## GitHub

Native Hierarchie über Sub-Issues; CLI-Grundlagen (`gh issue create/view/list/comment/edit/close`, Labels) in `issue-tracker.md`.

- **Epic**: ein Issue pro Feature, Label `epic`, Body wie oben. Kinder als native Sub-Issues (`gh api` Sub-issues-Endpunkt); wo Sub-Issues nicht verfügbar, Task-List im Epic-Body und `Part of #<epic>` am Kopf jedes Child-Bodys.
- **Arbeitsticket**: ein Issue pro Ticket via `gh issue create`, Label `ready-for-agent` (sofern nicht anders angewiesen), Kind des Epics, in Abhängigkeitsreihenfolge.
- **Blocking**: native Issue-Dependencies (`gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`; Datenbank-ID via `gh api repos/<owner>/<repo>/issues/<n> --jq .id`); wo nicht verfügbar, `Blocked by: #<n>, #<n>`-Zeile am Child-Kopf. Unblocked, wenn alle Blocker closed.
- **Frontier-Query**: offene Kinder des Epics listen, aussortieren: offener Blocker (`issue_dependencies_summary.blocked_by > 0` oder offenes Issue in der `Blocked by`-Zeile) oder Assignee; Abhängigkeitsreihenfolge zuerst.
- **Claim**: `gh issue edit <n> --add-assignee @me` — die erste Schreiboperation der Session. Der Assignee **ist** der Claim.
- **Status**: `ready-for-agent` ist ein Label (`--add-label` / `--remove-label`); `claimed` = Assignee gesetzt; `resolved` = Issue geschlossen.
- **Kommentar**: `gh issue comment <n> --body "..."`.
- **Resolve**: Kommentar (gebaut, Testzahlen, Commit-Hashes, Review-Verdikt, PR-Link), dann `gh issue close <n>`. Der PR selbst wird von `implement-ticket` erstellt, **gemergt** wird erst in secure-feature Umsetzung Sub-Step 4.

## GitLab

Auf Tiers mit nativen Epics echte Epics; CLI-Grundlagen (`glab issue create/view/list/note/update/close`) in `issue-tracker.md`.

- **Epic**: ein Epic pro Feature (`glab epic create`), Description wie oben; sonst ein Issue mit Label `epic`. Kinder: auf dem Epic erfassen bzw. `Part of #<epic>` am Description-Kopf.
- **Arbeitsticket**: ein Issue pro Ticket via `glab issue create`, Label `ready-for-agent` (sofern nicht anders angewiesen), in Abhängigkeitsreihenfolge.
- **Blocking**: nativer Blocking-Link per Quick-Action als Note (`glab issue note <child> --message "/blocked_by #<blocker>"`); ohne Premium/Ultimate `Blocked by: #<n>, #<n>`-Zeile am Issue-Kopf. Unblocked, wenn alle Blocker closed.
- **Frontier-Query**: `glab issue list -F json` auf die Epic-Kinder eingeschränkt, aussortieren: offener Blocker (nativer Link oder `Blocked by`-Zeile) oder Assignee; Abhängigkeitsreihenfolge zuerst.
- **Claim**: `glab issue update <n> --assignee @me` — die erste Schreiboperation der Session. Der Assignee **ist** der Claim.
- **Status**: `ready-for-agent` ist ein Label (`--label` / `--unlabel`); `claimed` = Assignee gesetzt; `resolved` = Issue geschlossen.
- **Kommentar**: `glab issue note <n> --message "..."`.
- **Resolve**: Note (gebaut, Testzahlen, Commit-Hashes, Review-Verdikt, MR-Link), dann `glab issue close <n>`. Der MR selbst wird von `implement-ticket` erstellt, **gemergt** wird erst in secure-feature Umsetzung Sub-Step 4.
