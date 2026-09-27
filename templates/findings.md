# Findings — <Feature-Name>

> Contract, kein Dokument. **Wer schreibt:** `security-review` (Tabelle „Findings", IDs `SF-nn`) und `review-ticket` (Tabelle „Review-Notes", IDs `RV-nn`, append-only). **Wer liest:** `merge-app-docs` (→ Anwendungsdoku §13), Entwickler:in. **Regel:** ein `SF-nn` je Fund, in Walk-Reihenfolge (Mitigation → Coverage → Interface → New Surface); ein `RV-nn` je Review-Note, in Ticket-Reihenfolge. Diese Datei ist die Quelle der Wahrheit; die Findings-Tabelle in `ticket-update.md` ist die verdichtete Projektion fürs Ticket.

## Findings

| SF-nn | Referenz | Fundstelle | Risiko | Empfehlung | Status |
|---|---|---|---|---|---|
| SF-01 | `<TM-nn / AC-nn / IF-nn / AK-nn>` | `<Datei:Zeile oder Diff-Hunk>` | `hoch / mittel / niedrig` | `<eine Zeile>` | `offen / behoben / akzeptiert (<Begründung, durch wen>)` |

(keine Findings = Satz „Keine Findings." statt Tabelle)
