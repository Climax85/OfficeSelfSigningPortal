namespace OfficeSelfSigningPortal.WebUI.Authentication;

/// <summary>
/// Portal-Rollen. Die Werte sind fachlicher Identity-Bestandteil (REQ-09) und
/// werden ausschließlich aus IdP-Gruppen-Claims abgeleitet — das Portal vergibt
/// keine Rollen (OP-04).
/// </summary>
public static class PortalRoles
{
    public const string Submitter = "Einreicher";
    public const string Editor = "Bearbeiter";
    public const string Administrator = "Admin";
}
