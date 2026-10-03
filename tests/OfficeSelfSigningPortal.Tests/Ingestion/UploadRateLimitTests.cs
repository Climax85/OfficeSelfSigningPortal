using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using OfficeSelfSigningPortal.Tests.Support;
using OfficeSelfSigningPortal.WebUI.Authentication.Testing;
using OfficeSelfSigningPortal.WebUI.Ingestion;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Ingestion;

/// <summary>
/// Seam S1 (TM-14, SF-03, AK via Ticket 37): der Upload-Endpunkt begrenzt die
/// Einreichungs-Frequenz pro IdP-Identität (Fixed-Window, konfigurierbar).
/// Konfigurations-Override fährt PermitLimit auf 2, sodass die dritte
/// aufeinanderfolgende Einreichung mit 429 abgewiesen wird.
/// </summary>
[Trait("Category", "Integration")]
[Collection(IngestionS1Collection.CollectionName)]
public sealed class UploadRateLimitTests(IngestionS1Fixture fixture)
{
    [Fact]
    public async Task Post_UeberRateLimit_WirdMit429Abgewiesen()
    {
        // Arrange — TM-14: DoS am Upload-Kanal wird pro Einreicher begrenzt.
        // PermitLimit = 2 erlaubt zwei Uploads im Fenster; der dritte wird gedrosselt.
        var limitedFactory = fixture.Factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Ingestion:UploadRateLimitPermitLimit", "2");
            builder.UseSetting("Ingestion:UploadRateLimitWindowSeconds", "60");
        });
        var client = new SubmissionApiClient(
            limitedFactory.CreateClient(),
            user: "alice",
            groups: "Einreicher",
            email: "alice@example.test");
        var content = IngestionFiles.CreateValidMacroFile("xlsm");

        // Act — drei Uploads innerhalb des Fensters, alle vom selben Einreicher.
        var first = await client.PostSubmissionAsync("analyse-1.xlsm", content);
        var second = await client.PostSubmissionAsync("analyse-2.xlsm", content);
        var third = await client.PostSubmissionAsync("analyse-3.xlsm", content);

        // Assert — 201/201/429 in dieser Reihenfolge.
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        var thirdBody = await third.Content.ReadAsStringAsync();
        Assert.True(
            third.StatusCode == HttpStatusCode.TooManyRequests,
            $"Erwartet 429, erhalten {(int)third.StatusCode}: {thirdBody}");
    }

    [Fact]
    public async Task Post_VerschiedeneEinreicher_TeilenSichDasLimitNicht()
    {
        // Arrange — die Policy partitioniert pro IdP-Identität: ein zweiter
        // Einreicher bekommt ein eigenes Limit, das vom ersten unabhängig ist.
        var limitedFactory = fixture.Factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Ingestion:UploadRateLimitPermitLimit", "1");
            builder.UseSetting("Ingestion:UploadRateLimitWindowSeconds", "60");
        });
        var content = IngestionFiles.CreateValidMacroFile("xlsm");
        var alice = new SubmissionApiClient(
            limitedFactory.CreateClient(),
            user: "alice",
            groups: "Einreicher",
            email: "alice@example.test");
        var bob = new SubmissionApiClient(
            limitedFactory.CreateClient(),
            user: "bob",
            groups: "Einreicher",
            email: "bob@example.test");

        // Act — Alice erschöpft ihr Limit; Bobs erstes Upload bleibt erlaubt.
        var aliceFirst = await alice.PostSubmissionAsync("alice-1.xlsm", content);
        var bobFirst = await bob.PostSubmissionAsync("bob-1.xlsm", content);
        var aliceSecond = await alice.PostSubmissionAsync("alice-2.xlsm", content);

        // Assert
        Assert.Equal(HttpStatusCode.Created, aliceFirst.StatusCode);
        Assert.Equal(HttpStatusCode.Created, bobFirst.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, aliceSecond.StatusCode);
    }
}
