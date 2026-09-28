using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 (TC-01/AK via Ticket 03): gültiger Upload erzeugt einen persistierten
/// Analyseauftrag mit Status <c>Eingereicht</c>; die Persistenz wird über die
/// öffentliche Status-Schnittstelle (GET) verifiziert, nicht über die Datenbank.
/// </summary>
[Trait("Category", "Integration")]
[Collection(IngestionS1Collection.CollectionName)]
public sealed class UploadHappyPathTests(IngestionS1Fixture fixture)
{
    [Theory]
    [InlineData("analyse.xlsm", "xlsm")]
    [InlineData("bericht.docm", "docm")]
    [InlineData("folien.pptm", "pptm")]
    public async Task Post_ValideMakrodatei_WirdAlsEingereichtPersistiert(string fileName, string contentType)
    {
        // Arrange — TC-01: authentifizierter Einreicher lädt eine gültige Datei hoch.
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateValidMacroFile(contentType);

        // Act
        var response = await client.PostSubmissionAsync(fileName, content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        Assert.NotNull(body);
        Assert.NotEqual(Guid.Empty, body!.JobId);
        Assert.Equal(JobStatusNames.Eingereicht, body.Status);
        Assert.Null(body.Reason);

        // Persistenz über die öffentliche Schnittstelle: GET liefert denselben Vorgang.
        var persisted = await client.GetStatusAsync(body.JobId);
        Assert.Equal(body.JobId, persisted.JobId);
        Assert.Equal(JobStatusNames.Eingereicht, persisted.Status);
    }
}
