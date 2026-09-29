using System.Net;
using System.Net.Http.Headers;
using OfficeSelfSigningPortal.Tests.Review;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Download;

/// <summary>
/// Seam S1: Vorgangs-Downloads (UC-04, AK-04, TC-27). Original ab Upload,
/// signierte Datei ab Zustand <c>Signiert</c> innerhalb des 90-Tage-Fensters —
/// ausschließlich für den Einreicher (TM-17).
/// </summary>
[Trait("Category", "Integration")]
public sealed class DownloadEndpointsTests(ReviewS1Fixture fixture) : IClassFixture<ReviewS1Fixture>
{
    private static readonly byte[] OriginalContent = [0x50, 0x4B, 0x03, 0x04, 0x01];
    private static readonly byte[] SignedContent = [0x50, 0x4B, 0x05, 0x06, 0x02];

    private HttpClient ClientFor(string user, string groups)
    {
        var client = fixture.Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        return client;
    }

    [Fact]
    public async Task Original_Eigentuemer_ErhaeltBlobMitDateinamen()
    {
        // Arrange
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "privat.xlsm", OriginalContent);
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}/original");

        // Assert
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(OriginalContent, bytes);
        var disposition = response.Content.Headers.ContentDisposition;
        Assert.NotNull(disposition);
        Assert.Contains("privat.xlsm", disposition!.FileNameStar ?? disposition.FileName ?? string.Empty);
    }

    [Fact]
    public async Task Original_FremderNutzer_WirdMit403Abgewiesen()
    {
        // Arrange
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "privat.xlsm", OriginalContent);
        var client = ClientFor("submitter-2", groups: "Einreicher");

        // Act — auch Bearbeiter dürfen nicht laden (Download = Einreicher, AK-04).
        var einreicherResponse = await client.GetAsync($"/api/submissions/{jobId}/original");
        var editorResponse = await ClientFor("bearbeiter-1", groups: "Bearbeiter")
            .GetAsync($"/api/submissions/{jobId}/original");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, einreicherResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, editorResponse.StatusCode);
    }

    [Fact]
    public async Task Original_Anonym_WirdMit401Abgewiesen()
    {
        // Arrange
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "privat.xlsm", OriginalContent);

        // Act
        var response = await fixture.Factory.CreateClient().GetAsync($"/api/submissions/{jobId}/original");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Signed_NachSignierung_ErhaeltEigentuemerSigniertenBlob()
    {
        // Arrange — TC-27/AK-04: Vorgang Signiert mit signiertem Blob und Audit-Zeitstempel.
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "bericht.xlsm", OriginalContent);
        var signedArtifactId = Guid.NewGuid();
        await fixture.SeedSignedBlobAsync(signedArtifactId, SignedContent);
        await fixture.SeedSagaAsync(
            jobId, SagaStateNames.Signiert, "submitter-1", DateTimeOffset.UtcNow.AddHours(-1),
            signedArtifactId, fileName: "bericht.xlsm");
        await fixture.SeedAuditAsync(
            jobId, AuditCategories.Saga, $"{SagaStateNames.Signiert}: Signierung abgeschlossen",
            "system:signing-service", DateTimeOffset.UtcNow.AddHours(-1));

        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}/signed");

        // Assert
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(SignedContent, bytes);
        var disposition = response.Content.Headers.ContentDisposition;
        Assert.NotNull(disposition);
        var name = disposition!.FileNameStar ?? disposition.FileName ?? string.Empty;
        Assert.Contains("bericht-signiert.xlsm", name);
    }

    [Fact]
    public async Task Signed_OhneSignaturStatus_WirdMit409Abgewiesen()
    {
        // Arrange
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "bericht.xlsm", OriginalContent);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.ReviewAusstehend, "submitter-1", DateTimeOffset.UtcNow);
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}/signed");

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Signed_AelterAls90Tage_WirdMit410Abgewiesen()
    {
        // Arrange — AK-04: 90 Tage ab Signiert; der Audit-Zeitstempel liegt 91 Tage zurück.
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "alt.xlsm", OriginalContent);
        var signedArtifactId = Guid.NewGuid();
        await fixture.SeedSignedBlobAsync(signedArtifactId, SignedContent);
        var signedAt = DateTimeOffset.UtcNow.AddDays(-91);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.Signiert, "submitter-1", signedAt.AddHours(-1), signedArtifactId);
        await fixture.SeedAuditAsync(
            jobId, AuditCategories.Saga, $"{SagaStateNames.Signiert}: Signierung abgeschlossen",
            "system:signing-service", signedAt);

        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}/signed");

        // Assert
        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }

    [Fact]
    public async Task Signed_FehlenderBlob_WirdMit410Beantwortet()
    {
        // Arrange — Retention (Ticket 11) hat den Blob entfernt: Status widersprüchlich,
        // der Download darf nichts mehr ausliefern (Verteidigung in der Tiefe).
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "weg.xlsm", OriginalContent);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.Signiert, "submitter-1", DateTimeOffset.UtcNow.AddDays(-2), Guid.NewGuid());
        await fixture.SeedAuditAsync(
            jobId, AuditCategories.Saga, $"{SagaStateNames.Signiert}: Signierung abgeschlossen",
            "system:signing-service", DateTimeOffset.UtcNow.AddDays(-2));

        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}/signed");

        // Assert
        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }

    [Fact]
    public async Task Signed_FremderNutzer_WirdMit403Abgewiesen()
    {
        // Arrange
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "privat.xlsm", OriginalContent);
        var signedArtifactId = Guid.NewGuid();
        await fixture.SeedSignedBlobAsync(signedArtifactId, SignedContent);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.Signiert, "submitter-1", DateTimeOffset.UtcNow, signedArtifactId);
        await fixture.SeedAuditAsync(
            jobId, AuditCategories.Saga, $"{SagaStateNames.Signiert}: Signierung abgeschlossen",
            "system:signing-service", DateTimeOffset.UtcNow);

        // Act
        var response = await ClientFor("submitter-2", groups: "Einreicher")
            .GetAsync($"/api/submissions/{jobId}/signed");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Signed_UnbekannterVorgang_WirdMit404Beantwortet()
    {
        // Arrange
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{Guid.NewGuid()}/signed");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
