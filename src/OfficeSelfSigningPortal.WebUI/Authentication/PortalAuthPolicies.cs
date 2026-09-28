namespace OfficeSelfSigningPortal.WebUI.Authentication;

/// <summary>
/// zentrale AuthN/AuthZ-Policies (REQ-09, TM-17): serverseitig je Endpunkt,
/// keine rollenbezogenen Entscheidungen clientseitig.
/// </summary>
public static class PortalAuthPolicies
{
    public const string Submitter = nameof(Submitter);
    public const string Editor = nameof(Editor);
    public const string Administrator = nameof(Administrator);
}
