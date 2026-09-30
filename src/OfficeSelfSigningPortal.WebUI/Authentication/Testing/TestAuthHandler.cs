using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace OfficeSelfSigningPortal.WebUI.Authentication.Testing;

/// <summary>Optionen des Test-AuthHandlers (Fake-IdP für Seam S1).</summary>
public class TestAuthHandlerOptions : AuthenticationSchemeOptions
{
    /// <summary>Claim-Typ, in dem der Fake-IdP die Gruppenmitgliedschaften liefert.</summary>
    public string GroupClaimType { get; set; } = "groups";
}

/// <summary>
/// Fake-IdP für Seam S1 (AK-34): liefert ausschließlich Gruppen-Claims in
/// IdP-Form (Header <see cref="GroupsHeader"/>), aus denen die echte
/// <see cref="GroupRoleClaimsTransformation"/> die Rollen ableitet.
/// Aktiviert ausschließlich via Konfiguration "Auth:UseTestAuthHandler" —
/// niemals außerhalb der Test-Verdrahtung.
/// </summary>
public sealed class TestAuthHandler : AuthenticationHandler<TestAuthHandlerOptions>
{
    public const string SchemeName = "TestIdp";
    public const string UserHeader = "X-Test-User";
    public const string GroupsHeader = "X-Test-Groups";

    /// <summary>Optional: simuliert den E-Mail-Claim des IdP (Ticket 10, REQ-08).</summary>
    public const string EmailHeader = "X-Test-Email";

    /// <summary>
    /// Optional: simuliert einen falsch konfigurierten IdP, der Rollen-Claims
    /// direkt liefert (RV-05) — dürfen nach AK-32 keine Berechtigung erzeugen.
    /// </summary>
    public const string RolesHeader = "X-Test-Roles";

    public TestAuthHandler(
        IOptionsMonitor<TestAuthHandlerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(UserHeader, out var user) || string.IsNullOrWhiteSpace(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var identity = new ClaimsIdentity(SchemeName);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.ToString()));
        identity.AddClaim(new Claim("preferred_username", user.ToString()));

        if (Request.Headers.TryGetValue(GroupsHeader, out var groups))
        {
            foreach (var group in groups.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                identity.AddClaim(new Claim(Options.GroupClaimType, group));
            }
        }

        if (Request.Headers.TryGetValue(EmailHeader, out var email) && !string.IsNullOrWhiteSpace(email))
        {
            identity.AddClaim(new Claim(ClaimTypes.Email, email.ToString()));
        }

        if (Request.Headers.TryGetValue(RolesHeader, out var roles))
        {
            foreach (var role in roles.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                identity.AddClaim(new Claim(identity.RoleClaimType, role));
            }
        }

        var principal = new ClaimsPrincipal(identity);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        // AK-33/TC-09: anonymer Request wird abgewiesen (401), nichts wird angenommen.
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
