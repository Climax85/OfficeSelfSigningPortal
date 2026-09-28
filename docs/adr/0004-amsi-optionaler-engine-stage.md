# AMSI als optionaler Engine-Stage, nie als Pflicht

Datum: 2025-09-27

AMSI-Scanning läuft nicht in der Aspire/Linux-Topologie (Aspire supportet keine Windows-Container; MCR-Images enthalten keinen AMSI-Provider). Die `AmsiScanBridge` (.NET-Worker auf Windows-Host, RabbitMQ-angebunden) ist daher ein optionales Deployment-Profil, kein Bestandteil des Standard-Deployments. Standard ist die Linux-Baseline (ClamAV + YARA + Heuristik). Der Message-Contract ist engine-neutral mit Degradation: AMSI-Ausfall/Timeout erzeugt `Inconclusive` und erzwingt Review — niemals `Clean`. Begründung: Endpoint-AV auf den Clients ist eine zweite Kontrollinstanz, aber die Signier-Entscheidung fällt am Gate; Kunden mit höherem Schutzbedarf aktivieren die Bridge explizit. Die Semantik `Baseline-Clean ≠ Endpoint-AV-Clean` ist dokumentationspflichtig.

Considered Options: AMSI als Pflicht-Stage (scheitert technisch an der Topologie), AMSI ganz streichen (schwächt den Clean-Verdict, Verlagerung der Kontrolle an den Endpunkt).
