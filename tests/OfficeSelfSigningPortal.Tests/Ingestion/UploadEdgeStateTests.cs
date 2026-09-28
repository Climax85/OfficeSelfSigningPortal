using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 — Vorgänge mit Endzustand aus der Ingestion (Trait Integration, Persistenz):
/// korrumpierte Datei → Fehler mit technischem Grund (TC-05/AK-35);
/// makrofreie Datei → NichtSignierbar mit Hinweis, kein Fehlerzustand (TC-06/AK-36).
/// </summary>
[Trait("Category", "Integration")]
[Collection(IngestionS1Collection.CollectionName)]
public sealed class UploadEdgeStateTests(IngestionS1Fixture fixture)
{
    [Theory]
    [InlineData(false)] // Zufallsbytes: weder ZIP noch OLE
    [InlineData(true)]  // CFB-Header ohne lesbaren ZIP-Layer (korrumpiertes Legacy-OLE)
    public async Task Post_KorrupteDatei_WirdAlsFehlerMitTechnischemGrundPersistiert(bool cfbHeaderOnly)
    {
        // Arrange — TC-05/AK-35: korrumpierte OLE/OOXML-Datei → Status Fehler, kein Hang.
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateCorruptFile(cfbHeaderOnly);

        // Act
        var response = await client.PostSubmissionAsync("kaputt.xlsm", content);

        // Assert — der Vorgang existiert und trägt den Endzustand Fehler samt Grund.
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        Assert.NotNull(body);
        Assert.Equal(JobStatusNames.Fehler, body!.Status);
        Assert.False(string.IsNullOrWhiteSpace(body.Reason), "Fehlerzustand braucht einen technischen Grund (REQ-10).");

        // Persistenz über die öffentliche Schnittstelle.
        var persisted = await client.GetStatusAsync(body.JobId);
        Assert.Equal(JobStatusNames.Fehler, persisted.Status);
        Assert.Equal(body.Reason, persisted.Reason);
    }

    [Fact]
    public async Task Post_MakrofreieDatei_WirdAlsNichtSignierbarMitHinweisPersistiert()
    {
        // Arrange — TC-06/AK-36: makrofreie .xlsm → NichtSignierbar mit Hinweis, kein Fehler.
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateMacroFreeFile("xlsm");

        // Act
        var response = await client.PostSubmissionAsync("leer.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        Assert.NotNull(body);
        Assert.Equal(JobStatusNames.NichtSignierbar, body!.Status);
        Assert.Contains("Kein Makro", body.Reason, StringComparison.Ordinal);

        var persisted = await client.GetStatusAsync(body.JobId);
        Assert.Equal(JobStatusNames.NichtSignierbar, persisted.Status);
    }
}
