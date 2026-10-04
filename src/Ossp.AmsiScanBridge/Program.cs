using System.Net.Mime;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Ossp.AmsiScanBridge;

var builder = WebApplication.CreateBuilder(args);

// Konfiguration (AmsiScanBridge:Section). Im Dev-Betrieb werden Token + URL via
// Aspire-AppHost gesetzt; im Produktionsbetrieb via Umgebungsvariablen.
builder.Services
    .AddOptions<AmsiScanBridgeOptions>()
    .Bind(builder.Configuration.GetSection(AmsiScanBridgeOptions.SectionName))
    .Validate(
        o => !string.IsNullOrWhiteSpace(o.Token),
        "AmsiScanBridge:Token fehlt — Brücke verweigert den Start (CONVENTIONS §5, Fail-fast am Systemrand).")
    .ValidateOnStart();

// Form-Verarbeitung nicht nötig — Bytes kommen als application/octet-stream.
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 0;
});

// Plattformabhängige AMSI-Senke (F5, ADR-0004).
if (OperatingSystem.IsWindows())
{
    builder.Services.AddSingleton<IAmsiScanner, WindowsAmsiScanner>();
}
else
{
    builder.Services.AddSingleton<IAmsiScanner, NonWindowsAmsiScanner>();
}

var app = builder.Build();

// Body-Limit aus der Option anwenden (Kestrel-MAX-Body).
var bridgeOptions = app.Services.GetRequiredService<IOptions<AmsiScanBridgeOptions>>().Value;
app.Use(async (context, next) =>
{
    var maxBytes = bridgeOptions.MaxRequestBodyBytes;
    var feature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (feature is { IsReadOnly: false })
    {
        feature.MaxRequestBodySize = maxBytes;
    }

    await next(context);
});

// Auth-Token-Prüfung per Middleware (kein AuthenticationHandler nötig —
// konstante Vergleichszeit reicht und vermeidet Claims-Overhead). Bei
// fehlendem/falschem Token: 401 ohne Body.
app.Use(async (context, next) =>
{
    // /health ist explizit token-frei (Smoke-Check-Pfad, AK-57).
    if (context.Request.Path.StartsWithSegments(AmsiScanBridgeEndpoints.HealthPath))
    {
        await next(context);
        return;
    }

    if (!context.Request.Path.StartsWithSegments(AmsiScanBridgeEndpoints.ScanPath))
    {
        await next(context);
        return;
    }

    // /scan verlangt das Token.
    if (!TokenValidator.TryValidate(context.Request, bridgeOptions.Token, out var failure))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync(failure);
        return;
    }

    await next(context);
});

// Health-Endpoint (token-frei): Smoke-Check-Pfad für Profil hardened (AK-57).
app.MapGet(AmsiScanBridgeEndpoints.HealthPath, () => Results.Text("ok"));

// Scan-Endpoint: nimmt die Bytes entgegen, reicht sie an den Scanner weiter
// und antwortet im AMSI-Result-Vertrag (IF-10, kompatibel zum bestehenden
// AmsiScanEngine).
app.MapPost(AmsiScanBridgeEndpoints.ScanPath, async (
    HttpRequest request,
    IAmsiScanner scanner,
    CancellationToken cancellationToken) =>
{
    var contentName = request.Headers[AmsiScanBridgeEndpoints.ContentNameHeader].ToString();
    if (string.IsNullOrWhiteSpace(contentName))
    {
        return Results.BadRequest("Header X-Content-Name fehlt.");
    }

    using var ms = new MemoryStream();
    await request.Body.CopyToAsync(ms, cancellationToken);
    var bytes = ms.ToArray();

    var call = new AmsiScanCall(bytes, contentName, ContentType: "");
    var detection = await scanner.ScanAsync(call, cancellationToken);

    var body = detection.IsMalicious
        ? $"AMSI_RESULT:1:{(detection.Name ?? "AMSI-Detection")}"
        : "AMSI_RESULT:0";
    return Results.Text(body, MediaTypeNames.Text.Plain);
});

await app.RunAsync();

namespace Ossp.AmsiScanBridge
{
    /// <summary>
    /// Marker-Klasse, damit <see cref="Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory{TEntryPoint}"/>
    /// die Brücke ohne Reflection auf den auto-generierten Main-Typ laden kann.
    /// </summary>
    public partial class Program;

    /// <summary>
    /// Konstant-Zeit-Validierung des Token-Headers (verhindert Timing-Leaks).
    /// </summary>
    internal static class TokenValidator
    {
        public static bool TryValidate(HttpRequest request, string? expected, out string failure)
        {
            if (string.IsNullOrEmpty(expected))
            {
                failure = "Brücke nicht initialisiert: Token nicht konfiguriert.";
                return false;
            }

            if (!request.Headers.TryGetValue(AmsiScanBridgeEndpoints.TokenHeader, out var supplied)
                || string.IsNullOrEmpty(supplied))
            {
                failure = "Header X-Amsi-Bridge-Token fehlt.";
                return false;
            }

            var suppliedValue = supplied.ToString();
            if (!FixedTimeEquals(suppliedValue, expected))
            {
                failure = "Ungültiges X-Amsi-Bridge-Token.";
                return false;
            }

            failure = string.Empty;
            return true;
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            var diff = 0;
            for (var i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }
    }
}