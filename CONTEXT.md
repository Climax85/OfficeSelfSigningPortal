# OfficeSelfSigningPortal

Self-Service-Portal zur automatisierten Analyse und digitalen Signierung von MS-Office-Makros; Vorgänge laufen als event-getriebene Saga über Message-Bus durch Scan-, Review- und Signier-Stages.

## Language

**Vorgang**:
Ein eingereichter Analyse- und Signierauftrag für genau eine Office-Datei, identifiziert durch Vorgangs-ID.
_Avoid_: Ticket, Job, Case, Request

**Verdict**:
Das verdichtete Ergebnis der Analyse-Stage eines Vorgangs (`Clean`, `Suspicious`, `Malicious`, `Inconclusive`, `Error`).
_Avoid_: Befund, Urteil, Ergebnisstatus

**Engine-Stage**:
Eine einzelne Analyse-Komponente (ClamAV, YARA, Heuristik, AMSI-Bridge, oletools-Sidecar), deren Einzelergebnisse zum Verdict verdichtet werden.
_Avoid_: Scanner (als Sammelbegriff), Prüfer

**Baseline-Clean**:
Ein `Clean`-Verdict, das ausschließlich auf den Linux-Baseline-Engines beruht — ausdrücklich keine Aussage über Endpoint-AV-Erkennung.
_Avoid_: Sauber, frei

**Review**:
Die manuelle Prüfung eines Vorgangs mit Verdict `Suspicious` oder `Inconclusive` durch einen Bearbeiter mit den Entscheidungsoptionen `Freigeben`, `Ablehnen`, `Rückfrage`.
_Avoid_: Freigabe, Prüfschritt

**Golden File**:
Eine mit Office/signtool+SIP erzeugte Referenz-Signaturdatei, gegen die der `VbaProjectSigner` seine Ausgabe testet.
_Avoid_: Referenzdatei, Musterdatei

**Audit-Trail**:
Die append-only, hash-verkettete Protokollkette aller vorgangsrelevanten Ereignisse.
_Avoid_: Log, Protokoll
