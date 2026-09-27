# Test-Cases — <Feature-Name>

> Contract, kein Dokument. **Wer schreibt:** `secure-feature` (nach Akzeptanzkriterien und Grilling). **Wer liest:** `tdd`/`implement`, `security-review`, Ticket-Rückschreiben. **Profil:** `klein` und `groß`.
>
> **Abdeckungsregeln:** Jeder Abuse-Case `AC-nn` braucht mindestens einen `TC-nn` (Spalte „Abdeckt AC-nn"). `-` in dieser Spalte nur bei Tests ohne Security-Bezug — oder wenn die zugehörige Threat-Model-Zeile ebenfalls `AC-nn: -` trägt (dann deckt der Test die Gegenmaßnahme der `TM-nn`-Zeile ab). Edge-Cases und Negativfälle sind Pflichtbestandteil — jeder `UC-nn` [nur groß] und jede fachliche Validierung braucht mindestens einen.

## TC-Tabelle

| TC-nn | Testfall | Art | Erwartetes Ergebnis | REQ-nn | AC-nn |
|---|---|---|---|---|---|
| TC-01 | `<geprüfte Aktion in einem Satz>` | `Normalfall / Edge-Case / Negativfall` | `<erwartetes Ergebnis, ein Satz>` | `<REQ-nn oder ->` | `<AC-nn oder ->` |
