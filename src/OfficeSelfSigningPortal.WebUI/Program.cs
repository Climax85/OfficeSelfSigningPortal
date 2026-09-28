using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OfficeSelfSigningPortal.WebUI.Authentication;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using OfficeSelfSigningPortal.WebUI.Components;
using OfficeSelfSigningPortal.WebUI.Data;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddDbContext<PortalDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("portal")));

// AuthN/AuthZ (REQ-09, ADR-0001, TM-17): generisches OIDC, Rollen ausschließlich
// aus IdP-Gruppen-Claims (GroupRoleClaimsTransformation), serverseitige
// Policies je Endpunkt. FallbackPolicy = authentifiziert: kein anonymer
// Endpunkt ohne Threat-Model-Eintrag.
var useTestAuthHandler = builder.Configuration.GetValue<bool>("Auth:UseTestAuthHandler");

var authOptions = builder.Configuration
    .GetSection(PortalAuthOptions.SectionName)
    .Get<PortalAuthOptions>() ?? new PortalAuthOptions();

if (!useTestAuthHandler && string.IsNullOrWhiteSpace(authOptions.Authority))
{
    throw new InvalidOperationException(
        $"PortalAuth:Authority fehlt — bitte Aspire-AppHost oder Konfiguration prüfen (Abschnitt '{PortalAuthOptions.SectionName}').");
}

builder.Services.AddSingleton<IClaimsTransformation, GroupRoleClaimsTransformation>();

var authentication = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    });

if (useTestAuthHandler)
{
    // Seam S1 (AK-34): Test-AuthHandler als Fake-IdP, ausschließlich via Konfiguration aktiviert.
    authentication.AddScheme<TestAuthHandlerOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
    builder.Services.PostConfigure<Microsoft.AspNetCore.Authentication.AuthenticationOptions>(options =>
    {
        options.DefaultScheme = TestAuthHandler.SchemeName;
        options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
    });
}
else
{
    // Generischer OIDC-Client — kein provider-spezifischer Code (REQ-09, ADR-0001).
    authentication
        .AddCookie()
        .AddOpenIdConnect(options =>
        {
            options.Authority = authOptions.Authority;
            options.ClientId = authOptions.ClientId;
            if (!string.IsNullOrEmpty(authOptions.ClientSecret))
            {
                options.ClientSecret = authOptions.ClientSecret;
            }

            options.ResponseType = OpenIdConnectResponseType.Code;
            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;
            options.RequireHttpsMetadata = authOptions.RequireHttpsMetadata;
            options.TokenValidationParameters.NameClaimType = "preferred_username";
        });
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(PortalAuthPolicies.Submitter, policy => policy.RequireRole(PortalRoles.Submitter));
    options.AddPolicy(PortalAuthPolicies.Editor, policy => policy.RequireRole(PortalRoles.Editor));
    options.AddPolicy(PortalAuthPolicies.Administrator, policy => policy.RequireRole(PortalRoles.Administrator));
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapDefaultEndpoints();

if (useTestAuthHandler)
{
    // Seam S1: minimale Probe-Endpunkte für die Policy-Infrastruktur
    // (AK-09/AK-32 über HTTP prüfbar; das Review-API verdrahtet Ticket 07).
    var probes = app.MapGroup("/__test/authz");
    probes.MapGet("/submitter", () => Results.Ok()).RequireAuthorization(PortalAuthPolicies.Submitter);
    probes.MapGet("/editor", () => Results.Ok()).RequireAuthorization(PortalAuthPolicies.Editor);
    probes.MapGet("/administrator", () => Results.Ok()).RequireAuthorization(PortalAuthPolicies.Administrator);
}

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.RunAsync();

// Für Integrationstests (WebApplicationFactory) zugänglich machen.
public partial class Program;
