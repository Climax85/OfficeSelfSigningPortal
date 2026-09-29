using System.Security.Claims;
using MassTransit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OfficeSelfSigningPortal.WebUI.Authentication;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using OfficeSelfSigningPortal.WebUI.Audit;
using OfficeSelfSigningPortal.WebUI.Components;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WebUI.Download;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using OfficeSelfSigningPortal.WebUI.LiveStatus;
using OfficeSelfSigningPortal.WebUI.Notifications;
using OfficeSelfSigningPortal.WebUI.Review;
using Ossp.Audit;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// CascadingAuthenticationState: AuthenticationState für AuthorizeView in SSR-
// Prerendering und interaktiven Circuits verfügbar machen (sonst InvalidOperationException
// "Authorization requires a cascading parameter of type Task<AuthenticationState>").
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddDbContext<PortalDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("portal")));

// Audit-Trail (REQ-18): append-only, SHA-256-Hash-Kette in der portal-DB (Ticket 06).
// Upload-Ereignisse schreibt die Ingestion, Saga-Übergänge der WorkerService und
// Guard-Ablehnungen der SigningService in dieselbe Kette.
builder.Services.AddAuditTrail(builder.Configuration.GetConnectionString("portal")
    ?? throw new InvalidOperationException(
        "Connection String 'portal' fehlt — bitte Aspire-AppHost oder Konfiguration prüfen."));

builder.Services.AddOptions<IngestionOptions>().BindConfiguration(IngestionOptions.SectionName);
builder.Services.AddOptions<ReviewOptions>().BindConfiguration(ReviewOptions.SectionName);
builder.Services.AddOptions<LiveStatusOptions>().BindConfiguration(LiveStatusOptions.SectionName);
builder.Services.AddOptions<DownloadOptions>().BindConfiguration(DownloadOptions.SectionName);
builder.Services.AddOptions<NotificationOptions>().BindConfiguration(NotificationOptions.SectionName);
builder.Services.AddScoped<SubmissionService>();
builder.Services.AddScoped<ReviewService>();
builder.Services.AddScoped<DownloadService>();
builder.Services.AddScoped<NotificationService>();

// Live-Status-Kanal (IF-03, AK-02/AK-20): SignalR-Hub + Single-Replica-Wächter,
// der den Saga-State-Store pollt und Änderungen pushed (REQ-20 — ohne Backplane).
builder.Services.AddSignalR();
builder.Services.AddSingleton<StatusWatchTracker>();
builder.Services.AddHostedService<StatusChangeNotifier>();

// Rate-Limit des Rückfrage-Kanals (TM-02): Fixed-Window pro Nutzer, Partition
// nach IdP-Identität — die Policy löst pro Request aus der Konfiguration auf.
builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    // Verbindliche Ablehnung im Rückfrage-Kanal: 429 (TM-02) statt des
    // Framework-Defaults 503 (RejectionStatusCode).
    rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rateLimiterOptions.AddPolicy(ReviewEndpoints.RueckfrageRateLimitPolicy, context =>
    {
        var reviewOptions = context.RequestServices
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<ReviewOptions>>().Value;
        var userId = context.User.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier) ?? "anonymous";
        return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
            userId,
            _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = reviewOptions.RueckfrageRateLimitPermitLimit,
                Window = TimeSpan.FromSeconds(reviewOptions.RueckfrageRateLimitWindowSeconds),
                QueueLimit = 0,
            });
    });
});

// Review-API (Ticket 07): read-only Zugriff auf den Saga-State-Store (analysis_saga,
// worker-DB — siehe PostgresSagaReviewReader). Schreibzugriff hat ausschließlich die
// Saga selbst; Entscheidungen erreichen sie als Outbox-Nachrichten.
var sagaStateConnectionString = builder.Configuration.GetConnectionString("sagastate");
builder.Services.AddSingleton<ISagaReviewReader>(
    new PostgresSagaReviewReader(sagaStateConnectionString));

// ScanRequested-Publikation über die EF-Core-Outbox (REQ-11, TM-06): Staging vor
// SaveChanges — die Nachricht committet atomar mit dem Upload. Test-Suites setzen
// OsspBus:Transport=InMemory.
var transport = builder.Configuration.GetValue<string>("OsspBus:Transport") ?? "RabbitMQ";

builder.Services.AddMassTransit(x =>
{
    x.AddEntityFrameworkOutbox<PortalDbContext>(o =>
    {
        o.UsePostgres();
        o.QueryDelay = TimeSpan.FromSeconds(5);
        o.UseBusOutbox();
    });

    if (transport.Equals("InMemory", StringComparison.OrdinalIgnoreCase))
    {
        x.UsingInMemory((_, cfg) =>
        {
            // WebUI publiziert ausschließlich — keine Receive-Endpunkte.
        });
    }
    else
    {
        var rabbitMqConnectionString = builder.Configuration.GetConnectionString("rabbitmq")
            ?? throw new InvalidOperationException(
                "Connection String 'rabbitmq' fehlt — bitte Aspire-AppHost oder Konfiguration prüfen.");
        x.UsingRabbitMq((_, cfg) => cfg.Host(rabbitMqConnectionString));
    }
});

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
app.UseRateLimiter();
app.UseAntiforgery();

app.MapDefaultEndpoints();
app.MapSubmissionEndpoints();
app.MapReviewEndpoints();
app.MapAuditEndpoints();
app.MapDownloadEndpoints();
app.MapNotificationEndpoints();
app.MapHub<JobStatusHub>(JobStatusHub.Route);

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
