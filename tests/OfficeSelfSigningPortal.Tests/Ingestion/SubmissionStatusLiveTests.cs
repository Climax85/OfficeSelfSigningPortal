using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Review;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1: Status-Endpunkt mit Saga-Join (AK-01/AK-02, TC-01): Der führende
/// Status stammt aus dem Saga-State-Store, die Anreicherung um den fachlichen
/// Grund aus dem Audit-Trail (AK-05); Einsicht für Eigentümer, Bearbeiter und
/// Admin (AK-20, TC-40), Download-Referenz ab Signiert (AK-04).
/// </summary>
[Trait("Category", "Integration")]
public sealed class SubmissionStatusLiveTests(ReviewS1Fixture fixture) : IClassFixture<ReviewS1Fixture>
{
    private static readonly byte[] Content = [0x50, 0x4B, 0x03, 0x04];

    private HttpClient ClientFor(string user, string groups)
    {
        var client = fixture.Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        return client;
    }

    [Fact]
    public async Task Get_FuehrenderStatus_stammtAusDerSagaNichtAusDerUploadZeile()
    {
        // Arrange — Upload-Zeile sagt Eingereicht, die Saga führt bereits ScanLaeuft.
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "laufend.xlsm", Content);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.ScanLaeuft, "submitter-1", DateTimeOffset.UtcNow.AddMinutes(-2));
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();

        // Assert
        Assert.NotNull(payload);
        Assert.Equal(SagaStateNames.ScanLaeuft, payload!.Status);
        Assert.Null(payload.SignedArtifactId);
    }

    [Fact]
    public async Task Get_Ablehnung_liefertNachvollziehbarenGrundAusAudit()
    {
        // Arrange — AK-05: Review-Kommentar der Ablehnung steht im Audit-Detail.
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "verdacht.xlsm", Content);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.Abgelehnt, "submitter-1", DateTimeOffset.UtcNow.AddHours(-1));
        await fixture.SeedAuditAsync(
            jobId, AuditCategories.Saga, $"{SagaStateNames.Abgelehnt}: Review-Ablehnung",
            "bearbeiter-1", DateTimeOffset.UtcNow.AddHours(-1), detail: "AutoExec-Verdacht nicht ausgeräumt.");
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();

        // Assert
        Assert.NotNull(payload);
        Assert.Equal(SagaStateNames.Abgelehnt, payload!.Status);
        Assert.Equal("AutoExec-Verdacht nicht ausgeräumt.", payload.Reason);
        Assert.Equal($"{SagaStateNames.Abgelehnt}: Review-Ablehnung", payload.LastEvent);
    }

    [Fact]
    public async Task Get_Signiert_liefertSignedArtifactIdFuerDownload()
    {
        // Arrange — AK-04: die UI braucht die Referenz, um den Signatur-Download anzubieten.
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "sauber.xlsm", Content);
        var signedArtifactId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, SagaStateNames.Signiert, "submitter-1", DateTimeOffset.UtcNow, signedArtifactId);
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();

        // Assert
        Assert.NotNull(payload);
        Assert.Equal(SagaStateNames.Signiert, payload!.Status);
        Assert.Equal(signedArtifactId, payload.SignedArtifactId);
    }

    [Fact]
    public async Task Get_BearbeiterUndAdmin_duerfenEinsehen_FremderEinreicherNicht()
    {
        // Arrange — AK-20/TC-40: Zwei-Betrachter-Fall setzt nicht-eigentümerliche
        // Einsicht voraus; fremde Einreicher bleiben ausgeschlossen (TM-17).
        var (jobId, _) = await fixture.SeedJobAsync("submitter-1", "team.xlsm", Content);
        await fixture.SeedSagaAsync(jobId, SagaStateNames.ReviewAusstehend, "submitter-1", DateTimeOffset.UtcNow);

        // Act
        var editor = await ClientFor("bearbeiter-1", groups: "Bearbeiter").GetAsync($"/api/submissions/{jobId}");
        var admin = await ClientFor("admin-1", groups: "Admin").GetAsync($"/api/submissions/{jobId}");
        var fremderEinreicher = await ClientFor("submitter-2", groups: "Einreicher").GetAsync($"/api/submissions/{jobId}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, editor.StatusCode);
        Assert.Equal(HttpStatusCode.OK, admin.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, fremderEinreicher.StatusCode);
    }

    [Fact]
    public async Task Get_VorgangOhneSaga_fallbackAufUploadZeileMitGrund()
    {
        // Arrange — makrofreie Dateien erreichen keine Saga; Status + Grund kommen
        // aus der Upload-Zeile (AK-36-Verhalten der Ingestion).
        var (jobId, _) = await fixture.SeedJobAsync(
            "submitter-1", "makrofrei.xlsm", Content, JobStatus.NichtSignierbar,
            statusReason: "Kein Makro enthalten: Die Datei ist makrofrei und muss nicht signiert werden.");
        var client = ClientFor("submitter-1", groups: "Einreicher");

        // Act
        var response = await client.GetAsync($"/api/submissions/{jobId}");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();

        // Assert
        Assert.NotNull(payload);
        Assert.Equal(nameof(JobStatus.NichtSignierbar), payload!.Status);
        Assert.Equal("Kein Makro enthalten: Die Datei ist makrofrei und muss nicht signiert werden.", payload.Reason);
    }
}
