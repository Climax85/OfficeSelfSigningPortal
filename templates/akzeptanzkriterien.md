# Akzeptanzkriterien — <Feature-Name>

> Contract, kein Dokument. **Wer schreibt:** `secure-feature` (nach Grilling) oder Artefakt-Pass nach `to-tickets`. **Wer liest:** `tdd`/`implement`, `security-review`, Ticket-Rückschreiben. **Profil:** `klein` und `groß`.
>
> **Abdeckungsregeln:** Jede Anforderung `REQ-nn` braucht mindestens ein Kriterium. Jede Anforderung mit `Security: ja` braucht mindestens ein Kriterium mit `Art: security`. Security-Kriterien sind Pflichtbestandteil dieser einen Tabelle — keine Zusatzsektion. Jedes Kriterium: geprüfbar formuliert („Wenn …, dann …"), ein Satz.

## AK-Tabelle

| AK-nn | Kriterium | Art | Referenz |
|---|---|---|---|
| AK-01 | `<Wenn <Eingabe/Bedingung>, dann <erwartetes Verhalten>.>` | `fachlich / security` | `<REQ-nn / AC-nn>` |
