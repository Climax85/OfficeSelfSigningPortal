# Signing-Key: Direct Conjur REST mit JWT-AuthN, Key ausschließlich Memory-only

Datum: 2025-09-27

Der SigningService holt den PKCS#12 per Conjur REST-API direkt aus dem Prozess (kein CP-Agent, kein IIS-CCP) mit `authn-jwt` (Kubernetes: FileJWTProvider auf Service-Account-Token, kein Bootstrap-Geheimnis; Dev: API-Key als Env-Secret). Das Zertifikat wird pro Signing-Vorgang frisch abgerufen als base64-Variable, in `X509Certificate2` mit `EphemeralKeySet` im Arbeitsspeicher gehalten und nach Verwendung verwischt — niemals auf Disk, niemals gecacht. Resiliency: Polly Retry (exponentiell + Jitter) + Circuit Breaker; MassTransit-Redelivery als persistierender Puffer bei Vault-Ausfall; 401-nach-Refresh und 404 sind nicht transient und gehen früh in die Fault-Queue.

Considered Options: CyberArk CP (Unix-Socket-Agent — hostgebunden, untauglich für kurzlebige Container), klassisches CCP (Windows/IIS-Zentrale), Azure Key Vault (Fallback-Provider bleibt implementiert, aber sekundär).
