using System.Security.Claims;

namespace OfficeSelfSigningPortal.WebUI.Notifications;

/// <summary>
/// Benachrichtigungs-Endpunkt (UC-08, AK-08, REQ-08): In-Portal-Benachrichtigungen
/// des angemeldeten Nutzers — Eintritt in Endzustände oder Rückfragen der eigenen
/// Vorgänge. Authentifizierung zwingend (FallbackPolicy); die Ableitung selbst
/// filtert zusätzlich auf den sub-Claim des Nutzers (keine fremden Vorgänge).
/// </summary>
public static class NotificationEndpoints
{
    public static IEndpointRouteBuilder MapNotificationEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/notifications");
        api.MapGet("", GetNotificationsAsync);
        return api;
    }

    private static async Task<IResult> GetNotificationsAsync(
        ClaimsPrincipal user,
        NotificationService notifications,
        CancellationToken cancellationToken)
    {
        var submittedBy = user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new InvalidOperationException("sub-Claim (NameIdentifier) fehlt im authentifizierten Principal.");

        var items = await notifications.GetForUserAsync(submittedBy, cancellationToken);
        return Results.Ok(new NotificationListResponse(items));
    }
}
