using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 — Absicherung des Upload-/Status-Endpunkts (IF-01, REQ-09):
/// Anonym wird mit 401 abgewiesen (TC-09), ohne Einreicher-Rolle mit 403;
/// Vorgänge sind am sub-Claim gebunden (fremde Vorgänge: 403, unbekannt: 404).
/// </summary>
[Trait("Category", "Integration")]
[Collection(IngestionS1Collection.CollectionName)]
public sealed class UploadAuthZTests(IngestionS1Fixture fixture)
{
    [Fact]
    public async Task Post_Anonym_WirdMit401Abgewiesen()
    {
        // Arrange — TC-09: kein Upload wird ohne Authentifizierung angenommen.
        var client = fixture.Factory.CreateClient();

        // Act — der Token-Endpunkt unterliegt der FallbackPolicy (authentifiziert).
        var antiforgeryResponse = await client.GetAsync("/api/submissions/upload-token");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, antiforgeryResponse.StatusCode);
    }

    [Fact]
    public async Task Post_AuthentifiziertOhneEinreicherRolle_WirdMit403Abgewiesen()
    {
        // Arrange — REQ-09: Bearbeiter-Rolle darf nicht einreichen (Policy Submitter).
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "bob", groups: "Bearbeiter");
        var content = IngestionFiles.CreateValidMacroFile("xlsm");

        // Act
        var response = await client.PostSubmissionAsync("nicht-erlaubt.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_FremderVorgang_WirdMit403Abgewiesen()
    {
        // Arrange — Vorgang von alice einreichen, bob (anderer sub-Claim) liest.
        var alice = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var uploaded = await alice.PostSubmissionAsync("privat.xlsm", IngestionFiles.CreateValidMacroFile("xlsm"));
        uploaded.EnsureSuccessStatusCode();

        var bob = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "bob", groups: "Einreicher");

        // Act — JobId aus dem Body der Upload-Antwort.
        var uploadedBody = await uploaded.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        var response = await bob.GetStatusRawAsync(uploadedBody!.JobId);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_UnbekannteVorgangsId_WirdMit404Beantwortet()
    {
        // Arrange
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");

        // Act
        var response = await client.GetStatusRawAsync(Guid.NewGuid());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
