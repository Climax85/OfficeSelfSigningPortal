using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 (Ticket 10, REQ-08): Der E-Mail-Claim des IdP wird an der Upload-Kante
/// erfasst und landet als SubmitterEmail im ScanRequested-Vertrag (Anhang A) —
/// Zustellbasis der E-Mail-Benachrichtigung. Ohne Claim bleibt das Feld null
/// und der Versandpfad entscheidet selbstständig.
/// </summary>
[Trait("Category", "Integration")]
[Collection(IngestionS1Collection.CollectionName)]
public sealed class UploadEmailClaimTests(IngestionS1Fixture fixture)
{
    [Fact]
    public async Task Post_MitEmailClaim_versiehtScanRequestedMitSubmitterEmail()
    {
        // Arrange: Fake-IdP liefert den E-Mail-Claim (Header X-Test-Email, TestAuthHandler).
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher", email: "alice@example.org");
        var content = IngestionFiles.CreateValidMacroFile("xlsm");

        // Act
        var response = await client.PostSubmissionAsync("analyse.xlsm", content);

        // Assert: Upload angenommen und die Outbox-Nachricht führt die Adresse.
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        Assert.NotNull(body);
        Assert.True(
            await fixture.OutboxMessageBodyContainsAsync(body!.JobId, "ScanRequested", "alice@example.org"),
            "ScanRequested in der Outbox muss die Einreicher-Adresse führen.");
    }

    [Fact]
    public async Task Post_OhneEmailClaim_versendetScanRequestedMitNullAdresse()
    {
        // Arrange: IdP ohne E-Mail-Claim — der Vertrag bleibt gültig (nullable Feld).
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateValidMacroFile("xlsm");

        // Act
        var response = await client.PostSubmissionAsync("analyse.xlsm", content);

        // Assert: Upload läuft normal; die Nachricht führt keine Adresse
        // (MassTransit serialisiert camelCase; null-Werte werden geschrieben).
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        Assert.NotNull(body);
        var outboxBody = await fixture.GetOutboxMessageBodyAsync(body!.JobId, "ScanRequested");
        Assert.NotNull(outboxBody);
        Assert.Contains("\"submitterEmail\":null", outboxBody!.Replace(" ", string.Empty, StringComparison.Ordinal));
    }
}
