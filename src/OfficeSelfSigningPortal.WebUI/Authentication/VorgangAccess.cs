using System.Security.Claims;

namespace OfficeSelfSigningPortal.WebUI.Authentication;

/// <summary>
/// Zentrale serverseitige Zugriffsentscheidungen auf Vorgänge (TM-17):
/// ausschließlich serverseitig ausgeführt — niemals als clientseitige Rollenlogik.
/// Der Einreicher ist Eigentümer; Bearbeiter und Admin sehen Vorgänge zur
/// Prüfung (Dashboard-/Review-Kontext, TC-40/AK-20: zwei Nutzer sehen denselben Zustand).
/// </summary>
public static class VorgangAccess
{
    /// <summary>Status-Einsicht: Eigentümer, Bearbeiter oder Admin.</summary>
    public static bool CanView(ClaimsPrincipal user, string submittedBy)
        => IsOwner(user, submittedBy)
           || user.IsInRole(PortalRoles.Editor)
           || user.IsInRole(PortalRoles.Administrator);

    /// <summary>Download (AK-04): ausschließlich der Einreicher.</summary>
    public static bool CanDownload(ClaimsPrincipal user, string submittedBy)
        => IsOwner(user, submittedBy);

    private static bool IsOwner(ClaimsPrincipal user, string submittedBy)
        => string.Equals(
            user.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier),
            submittedBy,
            StringComparison.Ordinal);
}
