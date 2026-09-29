using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;

namespace OfficeSelfSigningPortal.Tests.Review;

/// <summary>
/// Seam S1: Rückfrage-Kanal Einreicher ↔ Saga (TC-24, TC-26, AK-49, TM-02) —
/// Antwort-Verdrahtung als Vertragsnachricht über die Outbox, XSS-Filter,
/// Besitz-AuthZ, Zustands-Precondition und Rate-Limit.
/// </summary>
public sealed class RueckfrageAnswerTests(ReviewS1Fixture fixture) : IClassFixture<ReviewS1Fixture>
{
    private HttpClient ClientFor(string user, string groups)
    {
        var client = fixture.Factory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, groups);
        return client;
    }

    private static HttpContent AnswerPayload(string answer)
        => new StringContent(
            JsonSerializer.Serialize(new { answer }),
            Encoding.UTF8,
            "application/json");

    [Fact]
    public async Task Answer_als_Einreicher_staged_EinreicherAntwortEingegangen_und_ReviewAudit()
    {
        // Arrange — TC-24: Einreicher antwortet auf eine Rückfrage; die Antwort
        // erreicht die Saga als Vertragsnachricht (Anhang-B-Übergang).
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "RueckfrageAusstehend", "alice", DateTimeOffset.UtcNow.AddMinutes(-5));
        var client = ClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.PostAsync($"/api/reviews/{jobId}/answer", AnswerPayload("Interne Vorlage"));

        // Assert
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await fixture.GetLatestOutboxBodyAsync("EinreicherAntwortEingegangen");
        Assert.NotNull(body);
        Assert.Contains(jobId.ToString(), body);
        Assert.Contains("alice", body);
        Assert.Contains("Interne Vorlage", body);
        Assert.True(await fixture.CountAuditEntriesAsync(jobId, "review") >= 1);
    }

    [Fact]
    public async Task Answer_mit_Markup_wird_escapet_und_enthaelt_keinen_aktiven_Inhalt()
    {
        // Arrange — TC-26/AK-49: Link-/Markup-Inhalte werden gefiltert, bevor sie
        // Bus, Audit-Trail oder Portal erreichen.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "RueckfrageAusstehend", "alice", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.PostAsync(
            $"/api/reviews/{jobId}/answer",
            AnswerPayload("<script>alert('x')</script> [klick](javascript:alert(1))"));

        // Assert
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var body = await fixture.GetLatestOutboxBodyAsync("EinreicherAntwortEingegangen");
        Assert.NotNull(body);
        Assert.Contains("lt;script", body);
        Assert.DoesNotContain("<script>", body);
        Assert.DoesNotContain("javascript:alert", body);
    }

    [Fact]
    public async Task Answer_fuer_fremden_Vorgang_wirdMit403Abgewiesen()
    {
        // Arrange — der Rückfrage-Kanal gehört dem Einreicher des Vorgangs.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "RueckfrageAusstehend", "alice", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "mallory", groups: "Einreicher");

        // Act
        var response = await client.PostAsync($"/api/reviews/{jobId}/answer", AnswerPayload("Übernahmeversuch"));

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "EinreicherAntwortEingegangen"));
    }

    [Fact]
    public async Task Answer_ohne_ausstehende_Rueckfrage_wirdMit409Abgewiesen()
    {
        // Arrange — Anhang B: Antworten sind ausschließlich aus RueckfrageAusstehend definiert.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "ReviewAusstehend", "alice", DateTimeOffset.UtcNow);
        var client = ClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.PostAsync($"/api/reviews/{jobId}/answer", AnswerPayload("Zu früh"));

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(0, await fixture.CountOutboxMessagesForJobAsync(jobId, "EinreicherAntwortEingegangen"));
    }

    [Fact]
    public async Task Answer_fuer_unbekannten_Vorgang_wirdMit404Abgewiesen()
    {
        // Arrange
        var client = ClientFor(user: "alice", groups: "Einreicher");

        // Act
        var response = await client.PostAsync($"/api/reviews/{Guid.NewGuid()}/answer", AnswerPayload("Hallo?"));

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Answer_ueber_RateLimit_wirdMit429Abgewiesen()
    {
        // Arrange — TM-02: Missbrauch des Rückfrage-Kanals (Workflow-Verstopfung)
        // wird pro Nutzer begrenzt. Fixture mit PermitLimit 2 fahren.
        var jobId = Guid.NewGuid();
        await fixture.SeedSagaAsync(jobId, "RueckfrageAusstehend", "alice", DateTimeOffset.UtcNow);
        var limitedFactory = fixture.Factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Review:RueckfrageRateLimitPermitLimit", "2");
            builder.UseSetting("Review:RueckfrageRateLimitWindowSeconds", "60");
        });
        var client = limitedFactory.CreateClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, "alice");
        client.DefaultRequestHeaders.Add(TestAuthHandler.GroupsHeader, "Einreicher");

        // Act: zwei Antworten erlaubt, die dritte wird gedrosselt.
        var first = await client.PostAsync($"/api/reviews/{jobId}/answer", AnswerPayload("Antwort 1"));
        var second = await client.PostAsync($"/api/reviews/{jobId}/answer", AnswerPayload("Antwort 2"));
        var third = await client.PostAsync($"/api/reviews/{jobId}/answer", AnswerPayload("Antwort 3"));

        // Assert
        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        var thirdBody = await third.Content.ReadAsStringAsync();
        Assert.True(
            third.StatusCode == HttpStatusCode.TooManyRequests,
            $"Erwartet 429, erhalten {(int)third.StatusCode}: {thirdBody}");
    }
}
