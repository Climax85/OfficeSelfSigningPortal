using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;

namespace OfficeSelfSigningPortal.Tests.Review;

/// <summary>
/// Seam S1: Bearbeiter-Dashboard-Daten (AK-06, TC-20, REQ-06) — offene Reviews
/// mit Alterungsanzeige, sortiert nach Einreichzeit; AuthZ über zentrale
/// Bearbeiter-Policy (AK-09).
/// </summary>
public sealed class ReviewDashboardTests(ReviewS1Fixture fixture) : IClassFixture<ReviewS1Fixture>
{
    private HttpClient ClientFor(string user, string groups)
    {
        var client = fixture.Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        return client;
    }

    [Fact]
    public async Task GetOpen_ohneBearbeiterClaim_wirdMit403Abgewiesen()
    {
        // Arrange — AK-09: Dashboard ist Bearbeiter-Bereich.
        var client = ClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.GetAsync("/api/reviews/open");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetOpen_mitBearbeiterClaim_liefertOffeneReviewsSortiertNachEinreichzeitMitAlter()
    {
        // Arrange — TC-20/AK-06: zwei offene Reviews (Suspicious + Rückfrage), ein
        // laufender und ein abgeschlossener Vorgang sind nicht "offen".
        var now = DateTimeOffset.UtcNow;
        var alt = Guid.NewGuid();
        var mittel = Guid.NewGuid();
        var signiert = Guid.NewGuid();
        var scanLaeuft = Guid.NewGuid();
        await fixture.SeedSagaAsync(alt, "ReviewAusstehend", "submitter-1", now.AddHours(-5));
        await fixture.SeedSagaAsync(mittel, "RueckfrageAusstehend", "submitter-2", now.AddMinutes(-30));
        await fixture.SeedSagaAsync(signiert, "Signiert", "submitter-3", now.AddDays(-2));
        await fixture.SeedSagaAsync(scanLaeuft, "ScanLaeuft", "submitter-4", now.AddMinutes(-2));
        var client = ClientFor(user: "bob", groups: "Bearbeiter");

        // Act
        var response = await client.GetAsync("/api/reviews/open");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<OpenReviewsTestResponse>();

        // Assert: nur offene Reviews, älteste zuerst, Alterungsanzeige vorhanden.
        Assert.NotNull(payload);
        Assert.Equal(2, payload!.Reviews.Count);
        Assert.Equal(alt, payload.Reviews[0].JobId);
        Assert.Equal(mittel, payload.Reviews[1].JobId);
        Assert.Equal("ReviewAusstehend", payload.Reviews[0].CurrentState);
        Assert.Equal("RueckfrageAusstehend", payload.Reviews[1].CurrentState);
        Assert.True(payload.Reviews[0].AgeMinutes >= 299);
        Assert.True(payload.Reviews[0].SubmittedAt <= payload.Reviews[1].SubmittedAt);
    }

    private sealed record OpenReviewItem(
        Guid JobId,
        string OriginalFileName,
        string SubmittedBy,
        DateTimeOffset SubmittedAt,
        long AgeMinutes,
        string CurrentState,
        string ContentType,
        long FileSizeBytes);

    private sealed record OpenReviewsTestResponse(List<OpenReviewItem> Reviews);
}
