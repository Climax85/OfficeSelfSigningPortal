namespace OfficeSelfSigningPortal.WebUI.Authentication;

/// <summary>
/// Konfiguration der generischen OIDC-Anbindung (REQ-09, ADR-0001):
/// Authority/ClientId pro Umgebung (Aspire-Injektion bzw. User-Secrets),
/// niemals provider-spezifischer Code.
/// </summary>
public sealed class PortalAuthOptions
{
    public const string SectionName = "PortalAuth";

    /// <summary>OIDC-Issuer (dev: Keycloak-Container, prod: Entra ID).</summary>
    public string Authority { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    /// <summary>Optional — der Dev-Client ist public (PKCE ohne Secret).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Metadaten nur per HTTPS beziehen (OIDC-Default). Ausschließlich der
    /// AppHost-Dev-IdP (Keycloak via http-Container-Endpoint) schaltet das
    /// explizit um — niemals hart codiert (Must-Fix Review-Runde 1).
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>Claim-Typ, in dem der IdP die Gruppenmitgliedschaften liefert.</summary>
    public string GroupClaimType { get; set; } = "groups";

    /// <summary>
    /// Ableitung Rollen aus Gruppen: IdP-Gruppenname/-ID → Portal-Rolle.
    /// Produktiv werden hier Entra-ID-Gruppen-IDs gemappt; der Dev-Realm nutzt
    /// gleichnamige Gruppen.
    /// </summary>
    public Dictionary<string, string> GroupRoleMap { get; set; } = new(StringComparer.Ordinal)
    {
        [PortalRoles.Submitter] = PortalRoles.Submitter,
        [PortalRoles.Editor] = PortalRoles.Editor,
        [PortalRoles.Administrator] = PortalRoles.Administrator,
    };
}
