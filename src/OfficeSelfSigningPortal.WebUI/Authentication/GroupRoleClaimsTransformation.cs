using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace OfficeSelfSigningPortal.WebUI.Authentication;

/// <summary>
/// Leitet die Portal-Rollen ausschließlich aus den IdP-Gruppen-Claims ab
/// (REQ-09, OP-04): andere Claims — auch direkt vom IdP gelieferte
/// Rollen-Claims — erzeugen keine Berechtigung. Einzige Stelle, an der
/// Role-Claims (ClaimTypes.Role) ins Principal gelangen.
/// </summary>
public sealed class GroupRoleClaimsTransformation : IClaimsTransformation
{
    private readonly PortalAuthOptions _options;

    public GroupRoleClaimsTransformation(IOptions<PortalAuthOptions> options)
    {
        _options = options.Value;
    }

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
        {
            // Vor dem Hinzufügen materialisieren: die Enumeration teilt sich die
            // Claims-Liste mit AddClaim/RemoveClaim und würde sonst invalidiert werden.
            var groups = principal.FindAll(_options.GroupClaimType).Select(c => c.Value).ToList();

            // Eingehende Role-Claims (z. B. App Roles aus IdP-Misconfig) erzeugen
            // keine Berechtigung — sie werden vor der Ableitung entfernt (AK-32, RV-05).
            foreach (var foreignRoleClaim in principal.FindAll(identity.RoleClaimType).ToList())
            {
                identity.RemoveClaim(foreignRoleClaim);
            }

            foreach (var group in groups.Distinct(StringComparer.Ordinal))
            {
                if (_options.GroupRoleMap.TryGetValue(group, out var role))
                {
                    identity.AddClaim(new Claim(identity.RoleClaimType, role));
                }
            }
        }

        return Task.FromResult(principal);
    }
}
