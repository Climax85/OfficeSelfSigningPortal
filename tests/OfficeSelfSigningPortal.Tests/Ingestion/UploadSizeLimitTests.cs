using System.Net;
using System.Net.Http.Json;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 — Größenlimit (TC-03/AK-37): exakt 25 MiB wird akzeptiert,
/// 25 MiB + 1 Byte wird mit Grund „Größenlimit" abgelehnt.
/// </summary>
public sealed class UploadSizeLimitTests
{
    // Muss zum produktiven Default von IngestionOptions.MaxFileSizeBytes passen (25 MiB).
    private const long LimitBytes = 25L * 1024 * 1024;

    [Fact]
    public async Task Post_DateiMitLimitPlusEinByte_WirdMitGrundGroeßenlimitAbgewiesen()
    {
        // Arrange — TC-03: 25 MB + 1 Byte, gültiges xlsm-Gerüst mit Padding.
        using var factory = new PortalWebFactory();
        var client = new SubmissionApiClient(factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateMacroFileOfSize("xlsm", LimitBytes + 1);

        // Act
        var response = await client.PostSubmissionAsync("grenze.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RejectionResponse>();
        Assert.NotNull(body);
        Assert.Contains("Größenlimit", body!.Reason, StringComparison.Ordinal);
    }
}

/// <summary>Exakt-Limit-Akzeptanz (TC-03/AK-37) — benötigt Persistenz (Trait Integration).</summary>
[Trait("Category", "Integration")]
[Collection(IngestionS1Collection.CollectionName)]
public sealed class UploadSizeLimitExactTests(IngestionS1Fixture fixture)
{
    private const long LimitBytes = 25L * 1024 * 1024;

    [Fact]
    public async Task Post_DateiMitExaktLimitGroesse_WirdAkzeptiert()
    {
        // Arrange — TC-03: exakt 25 MiB wird akzeptiert.
        var client = new SubmissionApiClient(fixture.Factory.CreateClient(), user: "alice", groups: "Einreicher");
        var content = IngestionFiles.CreateMacroFileOfSize("xlsm", LimitBytes);

        // Act
        var response = await client.PostSubmissionAsync("grenze.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<SubmissionStatusResponse>();
        Assert.Equal(JobStatusNames.Eingereicht, body!.Status);
    }
}
