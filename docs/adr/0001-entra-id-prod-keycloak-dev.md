# IdP-Strategie: Entra ID direkt in Prod, Keycloak nur als Dev-IdP

Datum: 2025-09-27

Das Portal spricht generisches OIDC (Authority/Metadaten per Konfiguration). Lokal läuft Keycloak als Container im Aspire-AppHost mit Realm-Import und Test-Usern; produktiv wird Entra ID direkt angebunden. Ein Keycloak-Broker vor Entra ID wurde abgelehnt: Betriebs-Overhead ohne aktuellen Bedarf, und der OIDC-Contract macht einen späteren Wechsel zur Konfigurationsänderung, nicht zu einem Code-Change.
