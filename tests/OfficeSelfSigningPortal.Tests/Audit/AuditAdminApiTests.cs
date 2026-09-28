using System.Net;
using System.Net.Http.Json;
using Npgsql;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Audit;

/// <summary>
/// Admin-Abruf des Audit-Trails über die WebUI (Seam S1/S5, TC-36/TC-37, AK-07/AK-18,
/// REQ-07/REQ-18): nur Admins dürfen abrufen; die Antwort trägt Ereignisse in
/// zeitlicher Reihenfolge plus das Ergebnis der Hash-Ketten-Prüfung.
/// </summary>
[Trait("Category", "Integration")]
[Collection(AuditS5Collection.CollectionName)]
public sealed class AuditAdminApiTests(AuditS5Fixture fixture)
{
    [Fact]
    public async Task Get_als_Admin_liefert_ereignisse_mit_erfolgreicher_hashkettenpruefung()
    {
        // Arrange — TC-36: Vorgang über den Upload-Endpunkt einreichen (schreibt den
        // Upload-Audit-Eintrag über denselben portal-DB-Pfad).
        var alice = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var uploaded = await alice.PostSubmissionAsync("doku.xlsm", IngestionFiles.CreateValidMacroFile("xlsm"));
        uploaded.EnsureSuccessStatusCode();
        var jobId = (await uploaded.Content.ReadFromJsonAsync<SubmissionStoredResponse>())!.JobId;

        // Act
        var admin = ErstelleClient(user: "otto", groups: "Admin");
        var response = await admin.GetAsync($"/api/audit/{jobId}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var trail = (await response.Content.ReadFromJsonAsync<AuditTrailResponse>())!;
        Assert.True(trail.ChainValid);
        Assert.Equal(trail.Events.Count, trail.EntriesChecked);
        Assert.Equal(jobId, trail.JobId);
        var ereignisse = trail.Events.Select(e => e.Ereignis).ToList();
        Assert.Contains(ereignisse, e => e.Contains("Upload persistiert", StringComparison.Ordinal));
        var uploadEintrag = trail.Events.Single(e => e.Category == "upload");
        Assert.Equal("alice", uploadEintrag.Aktor);
        // zeitliche Reihenfolge: aufsteigende Ids
        Assert.Equal(trail.Events.OrderBy(e => e.Id).Select(e => e.Id), trail.Events.Select(e => e.Id));
    }

    [Fact]
    public async Task Get_ohne_AdminRolle_wird_mit_403_abgewiesen()
    {
        // Arrange — REQ-09: Bearbeiter-Rolle darf den Audit-Trail nicht abrufen.
        var jobId = Guid.NewGuid();
        var bearbeiter = ErstelleClient(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await bearbeiter.GetAsync($"/api/audit/{jobId}");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Get_nach_direkter_DB_Manipulation_meldet_ungueltige_kette()
    {
        // Arrange — TC-37: Eintrag direkt in der Datenbank verändern, Admin-Abruf muss
        // die Manipulation als fehlgeschlagene Ketten-Prüfung melden.
        var jobId = Guid.NewGuid();
        await fixture.Writer.AppendAsync(jobId, "saga", "Scan Clean — Auto-Signierung", "system:auto-sign", "score=5", CancellationToken.None);

        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE audit_trail SET \"Ereignis\" = 'Scan Clean — Auto-Signierung (nachbearbeitet)' WHERE \"JobId\" = @jobId",
                connection);
            command.Parameters.AddWithValue("jobId", jobId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        // Act
        var admin = ErstelleClient(user: "otto", groups: "Admin");
        var response = await admin.GetAsync($"/api/audit/{jobId}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var trail = (await response.Content.ReadFromJsonAsync<AuditTrailResponse>())!;
        Assert.False(trail.ChainValid);
        Assert.NotNull(trail.BrokenAtEntryId);
    }

    [Fact]
    public async Task Get_fuer_unbekannten_vorgang_liefert_leere_ereignisse_mit_valider_kette()
    {
        // Arrange
        var admin = ErstelleClient(user: "otto", groups: "Admin");

        // Act
        var response = await admin.GetAsync($"/api/audit/{Guid.NewGuid()}");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var trail = (await response.Content.ReadFromJsonAsync<AuditTrailResponse>())!;
        Assert.True(trail.ChainValid);
        Assert.Empty(trail.Events);
    }

    private HttpClient ErstelleClient(string user, string groups)
    {
        var client = fixture.Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        return client;
    }

    private sealed record SubmissionStoredResponse(Guid JobId);

    private sealed record AuditTrailResponse(
        Guid JobId,
        bool ChainValid,
        int EntriesChecked,
        long? BrokenAtEntryId,
        IReadOnlyList<AuditEventResponse> Events);

    private sealed record AuditEventResponse(
        long Id,
        DateTimeOffset OccurredAt,
        string Category,
        string Ereignis,
        string Aktor,
        string? Detail);
}
