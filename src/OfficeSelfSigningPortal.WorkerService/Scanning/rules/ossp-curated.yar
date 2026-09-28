// Kuratiertes YARA-Regelwerk des OSSP-Scanners (TM-05).
//
// Stand: scoring-v0.1;ruleset-2025-09 (siehe Scanning:Scoring:ScoreVersion).
// Kuratierung bewusst schmal gehalten: nur generische Struktur-Verdachtsregeln
// (SANS-inspiriert, FP-diszipliniert nach YARA-Performance-Guidelines). Das vollständige
// kuratierte signature-base-Subset (Familien-/Campaign-Regeln mit IsFamily: true im
// Score-Mapping) wird betrieblich gemountet — Scanning:Engines:YaraRulesPath zeigt dann
// auf die Regeldatei des Deployments, das Regelname→Score-Mapping bleibt Config unter
// Versionskontrolle (Anhang D). Jede Regelwerks-Änderung erzeugt eine neue ScoreVersion.

rule Contains_VbaProject_Ooxml
{
    meta:
        description = "OOXML-Paket enthält einen vbaProject.bin-Eintrag (generischer Verdacht, FP-behaftet)"
        score = 10
    strings:
        $vba = "vbaProject.bin" ascii
    condition:
        $vba
}
