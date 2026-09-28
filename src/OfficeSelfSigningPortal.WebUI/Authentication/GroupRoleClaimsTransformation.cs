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
            // Claims-Liste mit AddClaim und würde sonst invalidiert werden.
            var groups = principal.FindAll(_options.GroupClaimType).Select(c => c.Value).ToList();
            foreach (var group in groups)
            {
                if (_options.GroupRoleMap.TryGetValue(group, out var role) && !principal.IsInRole(role))
                {
                    identity.AddClaim(new Claim(identity.RoleClaimType, role));
                }
            }
        }

        return Task.FromResult(principal);
    }
}
