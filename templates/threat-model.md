# Threat Model — <Feature-Name>

> Contract, kein Dokument. **Wer schreibt:** `threat-model`. **Wer liest:** `security-review`, Entwickler:in (bestätigt Schnittstellen). **Profil:** Abschnitte markiert `[immer]` bzw. `[nur groß]` — im Profil `klein` entfallen die `[nur groß]`-Abschnitte.

## STRIDE [immer]

| TM-nn | Kategorie | Bedrohung | Asset | Auswirkung | Risiko | Gegenmaßnahme | AC-nn | Status |
|---|---|---|---|---|---|---|---|---|
| TM-01 | `<Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege>` | `<Bedrohung in einem Satz>` | `<was wird angegriffen>` | `<Schaden in einem Satz>` | `hoch / mittel / niedrig` | `<Gegenmaßnahme oder "keine">` | `<zugeordneter Abuse-Case oder ->` | `offen / umgesetzt / akzeptiert` |

**Stop-Regel:** `Risiko: hoch` mit `Gegenmaßnahme: keine` ist eine harte Stop-Stelle — der Workflow bricht ab, bis die Entwickler:in entschieden hat (Gegenmaßnahme, Risikoakzeptanz mit Begründung oder Scope-Änderung).

## Neue Schnittstellen/Datenflüsse [immer]

Pflichtabschnitt: Jede vom Feature neu eingeführte Schnittstelle muss hier eingetragen und in die Anwendungsdoku nachgemeldet werden. Der Agent *schlägt* Einträge aus dem Anforderungs-/Grilling-Kontext vor, die Entwickler:in bestätigt oder korrigiert — nichts wird leer erfragt.

| IF-nn | Schnittstelle/Datenfluss | Richtung | Daten | Authentisierung | Status |
|---|---|---|---|---|---|
| IF-01 | `<Endpunkt, Queue, Datei-Export, …>` | `eingehend / ausgehend / intern` | `<welche Daten>` | `<Methode oder "nein">` | `vorgeschlagen / bestätigt / korrigiert` |

## Betriebsrelevante Festlegungen [immer]

Pflichtabschnitt: Jede beim Grilling bestätigte Festlegung mit Zielabschnitt in der Anwendungsdokumentation (§4.1 Übersichtsdiagramm, §4.2 Technologie-Stack, §6 Authentisierung/Autorisierung inkl. Subsections, §8 Kryptografie, §10 Konfiguration/Hardening, §14 Betriebshandbuch inkl. Subsections, ggf. Anhang A–C). Subsection-Namen erlaubt (z. B. `§6.1`, `§14.3`). Features, die den Tech-Stack festlegen oder Kryptografie nutzen, müssen §4.2-/§8-Zeilen mit den konkreten Fakten (Algorithmus, Bibliothek, Schlüssellänge) vorschlagen. Der Agent *schlägt* Einträge aus dem Anforderungs-/Grilling-Kontext vor, die Entwickler:in bestätigt oder korrigiert — nichts wird leer erfragt. Feeds `merge-app-docs` (Bullets unter dem genannten Zielabschnitt).

| OP-nn | Zielabschnitt | Festlegung | Status |
|---|---|---|---|
| OP-01 | `<§4.1 / §6 / §10 / §14 / Anhang X>` | `<eine Festlegung, ein Satz>` | `vorgeschlagen / bestätigt / korrigiert` |

## Annahmen und Abgrenzung [nur groß]

- `<was dieses Modell bewusst nicht abdeckt und warum>`
