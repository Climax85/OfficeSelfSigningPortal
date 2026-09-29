using System.Net;
using System.Text;
using System.Text.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;

namespace OfficeSelfSigningPortal.Tests.Review;

/// <summary>
/// Seam S1: Review-Entscheidungen der Bearbeiter (TC-21/TC-23, AK-03/AK-05/AK-09/AK-17)
/// — Validierung, Zustands-Precondition, SoD-Frühabweisung, AuthZ-Vorfall-Protokoll
/// (TC-25) und Outbox-Staging der Vertragsnachricht.
/// </summary>
public sealed class ReviewDecisionTests(ReviewS1Fixture fixture) : IClassFixture<ReviewS1Fixture>
{
    private HttpClient ClientFor(string user, string groups)
    {
        var client = fixture.Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        return client;
    }

    private static HttpContent DecisionPayload(string? decision, string? comment)
        => new StringContent(
            JsonSerializer.Serialize(new { decision, comment }),
            Encoding.UTF8,
            "application/json");

    [Fact]
    public async Task Decide_Freigeben_durch_Bearbeiter_staged_ReviewDecisionRecorded_und_ReviewAudit()
    {
        // Arrange — TC-21: berechtigter zweiter Bearbeiter entscheidet Freigeben.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "submitter-1", DateTimeOffset.UtcNow.AddMinutes(-10));
        var client = ClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Freigeben", comment: null));

        // Assert: angenommen, Vertragsnachricht über die Outbox gestaged, Intake auditiert.
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await fixture.GetLatestOutboxBodyAsync("ReviewDecisionRecorded");
        Assert.NotNull(body);
        Assert.Contains(jobId.ToString(), body);
        Assert.Contains("bob", body);
        Assert.Contains("Freigeben", body);
        Assert.True(await fixture.CountAuditEntriesAsync(jobId, "review") >= 1);
    }

    [Fact]
    public async Task Decide_Ablehnen_mit_Begruendung_escapet_Markup_und_staged_mit_Grund()
    {
        // Arrange — TC-23/AK-05: Ablehnung mit Begründung; aktive Inhalte im
        // Kommentar werden gefiltert (Vorbereitung AK-49-Anzeige im Portal).
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "submitter-1", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Ablehnen", "<b>Verdacht</b> auf Exfiltration"));

        // Assert
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await fixture.GetLatestOutboxBodyAsync("ReviewDecisionRecorded");
        Assert.NotNull(body);
        Assert.Contains("Ablehnen", body);
        Assert.Contains("lt;b", body);
        Assert.DoesNotContain("<b>", body);
    }

    [Fact]
    public async Task Decide_Ablehnen_ohne_Begruendung_wirdMit422Abgewiesen()
    {
        // Arrange — REQ-17: Ablehnen setzt eine nachvollziehbare Begründung voraus.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "submitter-1", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Ablehnen", comment: "  "));

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "ReviewDecisionRecorded"));
    }

    [Fact]
    public async Task Decide_mit_ungueltigem_Entscheidungswert_wirdMit422Abgewiesen()
    {
        // Arrange — Anhang A definiert exakt drei Entscheidungswerte.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "submitter-1", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Vielleicht", comment: null));

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "ReviewDecisionRecorded"));
    }

    [Fact]
    public async Task Decide_in_falschem_Zustand_wirdMit409Abgewiesen_und_nichts_gestaged()
    {
        // Arrange — Anhang B: Entscheidungen sind nur aus ReviewAusstehend definiert.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "SignierungAngefragt", "submitter-1", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Freigeben", comment: null));

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "ReviewDecisionRecorded"));
    }

    [Fact]
    public async Task Decide_Freigeben_durch_Einreicher_SoD_wirdMit409Abgewiesen_und_Guard_auditet()
    {
        // Arrange — TC-22 (API-Teil)/AK-17: Freigabe der eigenen Datei ist am API
        // bereits blockiert; die Saga bleibt der letzte Sicherheitsring.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "alice", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "alice", groups: "Einreicher,Bearbeiter");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Freigeben", comment: null));

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "ReviewDecisionRecorded"));
        Assert.True(await fixture.CountAuditEntriesAsync(jobId, "guard") >= 1);
    }

    [Fact]
    public async Task Decide_ohne_BearbeiterClaim_wirdMit403Abgewiesen_und_Vorfall_protokolliert()
    {
        // Arrange — TC-25/AK-09: keine Bearbeiter-Rolle → 403, keine Zustands-
        // änderung, der Vorfall liegt im Audit-Trail (Kategorie guard).
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "submitter-1", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/decision",
            DecisionPayload("Ablehnen", "Unbefugter Versuch"));

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "ReviewDecisionRecorded"));
        Assert.True(await fixture.CountAuditEntriesAsync(jobId, "guard") >= 1);
        Assert.Equal(0, await fixture.CountAuditEntriesAsync(jobId, "review"));
    }
}
