using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Review;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using Ossp.Audit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.Tests.Notifications;

/// <summary>
/// Seam S1: In-Portal-Benachrichtigungen (UC-08, AK-08, REQ-08) — Eintritt in
/// Endzustände oder Rückfragen der eigenen Vorgänge, abgeleitet aus dem
/// Audit-Trail; Sichtbarkeit strikt auf den eigenen sub-Claim beschränkt.
/// </summary>
[Trait("Category", "Integration")]
public sealed class NotificationEndpointsTests(ReviewS1Fixture fixture) : IClassFixture<ReviewS1Fixture>
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
    public async Task Get_EigenenVorgaenge_EndzustandUndRueckfrage_sindEnthaltenNichtAberLaufende()
    {
        // Arrange — alice: Signiert + Rückfrage + laufender Scan (irrelevant);
        // bob: Ablehnung (darf nicht erscheinen).
        var now = DateTimeOffset.UtcNow;
        var (signiert, _) = await fixture.SeedJobAsync("alice", "sauber.xlsm", Content);
        var (rueckfrage, _) = await fixture.SeedJobAsync("alice", "unklar.xlsm", Content);
        var (laufend, _) = await fixture.SeedJobAsync("alice", "scan.xlsm", Content);
        var (fremd, _) = await fixture.SeedJobAsync("bob", "fremd.xlsm", Content);

        await fixture.SeedAuditAsync(signiert, AuditCategories.Saga, $"{SagaStateNames.Signiert}: Signierung abgeschlossen", "system:signing-service", now.AddMinutes(-5));
        await fixture.SeedAuditAsync(rueckfrage, AuditCategories.Saga, $"{SagaStateNames.RueckfrageAusstehend}: Review-Rückfrage gestellt", "bearbeiter-1", now.AddMinutes(-2), detail: "Bitte Zweck des Makros erläutern.");
        await fixture.SeedAuditAsync(laufend, AuditCategories.Saga, $"{SagaStateNames.ScanLaeuft}: Validierung abgeschlossen — Scan startet", "system:saga", now.AddMinutes(-1));
        await fixture.SeedAuditAsync(fremd, AuditCategories.Saga, $"{SagaStateNames.Abgelehnt}: Review-Ablehnung", "bearbeiter-1", now);

        var client = ClientFor("alice", groups: "Einreicher");

        // Act
        var response = await client.GetAsync("/api/notifications");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<NotificationListTestResponse>();

        // Assert: nur benachrichtigungsrelevante Ereignisse eigener Vorgänge, neueste zuerst.
        Assert.NotNull(payload);
        Assert.Equal(2, payload!.Notifications.Count);
        Assert.Equal(rueckfrage, payload.Notifications[0].JobId);
        Assert.Equal(SagaStateNames.RueckfrageAusstehend, payload.Notifications[0].State);
        Assert.Equal("Bitte Zweck des Makros erläutern.", payload.Notifications[0].Detail);
        Assert.Equal(signiert, payload.Notifications[1].JobId);
        Assert.Equal(SagaStateNames.Signiert, payload.Notifications[1].State);
        Assert.DoesNotContain(payload.Notifications, n => n.JobId == laufend);
        Assert.DoesNotContain(payload.Notifications, n => n.JobId == fremd);
    }

    [Fact]
    public async Task Get_ohneEigeneVorgaenge_liefertLeereListe()
    {
        // Arrange
        var client = ClientFor("neu-nutzer", groups: "Einreicher");

        // Act
        var response = await client.GetAsync("/api/notifications");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<NotificationListTestResponse>();

        // Assert
        Assert.NotNull(payload);
        Assert.Empty(payload!.Notifications);
    }

    [Fact]
    public async Task Get_Anonym_WirdMit401Abgewiesen()
    {
        // Act
        var response = await fixture.Factory.CreateClient().GetAsync("/api/notifications");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private sealed record NotificationItemTest(
        Guid JobId,
        string OriginalFileName,
        string State,
        string Message,
        string? Detail,
        DateTimeOffset OccurredAt);

    private sealed record NotificationListTestResponse(List<NotificationItemTest> Notifications);
}
