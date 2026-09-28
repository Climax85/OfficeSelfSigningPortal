using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 — Upload-Regel-Verletzungen (REQ-10, REQ-23): Ablehnung mit eindeutigem,
/// nachvollziehbarem Grund; kein Vorgang angelegt, kein Scan gestartet.
/// Läuft ohne Datenbank: Ablehnungen persistieren nichts.
/// </summary>
public sealed class UploadRejectionTests(PortalWebFactory factory) : IClassFixture<PortalWebFactory>
{
    [Fact]
    public async Task Post_ExeDatei_WirdMitGrundFormatNichtErlaubtAbgewiesen()
    {
        // Arrange — TC-02: Upload einer .exe-Datei.
        var client = new SubmissionApiClient(factory.CreateClient(), user: "alice", groups: "Einreicher");

        // Act
        var response = await client.PostSubmissionAsync("programm.exe", [0x4D, 0x5A, 0x90, 0x00]);

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RejectionResponse>();
        Assert.NotNull(body);
        Assert.Contains("Format nicht erlaubt", body!.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(Guid.Empty.ToString(), response.Headers.Location?.ToString() ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Post_DateiOhneBekannteEndung_WirdMitGrundFormatNichtErlaubtAbgewiesen()
    {
        // Arrange — REQ-10: auch harmlos wirkende Endungen sind nicht zugelassen.
        var client = new SubmissionApiClient(factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateValidMacroFile("xlsm");

        // Act
        var response = await client.PostSubmissionAsync("tarnung.pdf", content);

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RejectionResponse>();
        Assert.Contains("Format nicht erlaubt", body!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Post_PasswortgeschuetzteDatei_WirdMitHinweisAufPasswortschutzAbgewiesen()
    {
        // Arrange — TC-04: passwortgeschützte Makro-Datei, kein Scan wird gestartet.
        var client = new SubmissionApiClient(factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreatePasswordProtectedFile();

        // Act
        var response = await client.PostSubmissionAsync("geschuetzt.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RejectionResponse>();
        Assert.NotNull(body);
        Assert.Contains("Passwort", body!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Post_ZipBombMuster_WirdVorScannerUebergabeAbgewiesen()
    {
        // Arrange — TC-07/AK-23: extremes Kompressionsverhältnis (512 MiB deklariert,
        // wenige KiB übertragen) — Ablehnung in der Ingestion, Scanner sehen die Datei nie.
        var client = new SubmissionApiClient(factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateZipBombFile(declaredUncompressedBytes: 512L * 1024 * 1024);

        // Act
        var response = await client.PostSubmissionAsync("bombe.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RejectionResponse>();
        Assert.NotNull(body);
        Assert.Contains("Zip-Bomb", body!.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Post_PolyglotMitOleUndZipLayout_WirdVorScannerUebergabeAbgewiesen()
    {
        // Arrange — TC-08/AK-23: CFB-Header mit lesbarem ZIP-Layer (Polyglot).
        var client = new SubmissionApiClient(factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreatePolyglotFile();

        // Act
        var response = await client.PostSubmissionAsync("zwitter.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RejectionResponse>();
        Assert.NotNull(body);
        Assert.Contains("Polyglot", body!.Reason, StringComparison.Ordinal);
    }
}
