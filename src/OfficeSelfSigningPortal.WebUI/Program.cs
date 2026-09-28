using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WebUI.Components;
using OfficeSelfSigningPortal.WebUI.Data;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddDbContext<PortalDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("portal")));

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseAntiforgery();

app.MapDefaultEndpoints();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.RunAsync();

// Für Integrationstests (WebApplicationFactory) zugänglich machen.
public partial class Program;
