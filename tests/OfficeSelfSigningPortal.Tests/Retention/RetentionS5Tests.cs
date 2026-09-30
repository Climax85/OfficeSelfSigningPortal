using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WorkerService.Retention;
using Ossp.Audit;
using Ossp.Contracts;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Retention;

/// <summary>
/// Seam S5 — Retention-Job auf Testcontainers-PostgreSQL (TC-38, AK-19, REQ-19):
/// 90 Tage nach Signierung löscht der Job Original- und Signatur-Blobs; der
/// Audit-Bestand (Scan-Ergebnisse, Signier-Evidenz, Übergänge) bleibt unverändert
/// und hash-verkettet bestehen. Die Löschung selbst wird als Audit-Eintrag
/// protokolliert (REQ-18) und ist idempotent.
/// </summary>
[Trait("Category", "Integration")]
[Collection(RetentionS5Collection.CollectionName)]
public sealed class RetentionS5Tests(RetentionS5Fixture fixture)
{
    private static readonly DateTimeOffset Jetzt = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task ExecuteAsync_90_Tage_nach_Signierung_löscht_Original_und_Signatur_Blobs()
    {
        // Arrange — TC-38: Vorgang wurde signiert, die Frist ist abgelaufen
        var jobId = Guid.NewGuid();
        var originalId = Guid.NewGuid();
        var signaturId = Guid.NewGuid();
        var signedAt = Jetzt.AddDays(-91);

        await fixture.SeedSignierteSagaAsync(jobId, originalId, signaturId, receivedAt: signedAt);
        await fixture.SeedArtifactsAsync(
            NeuesArtefakt(originalId),
            NeuesArtefakt(signaturId));
        await fixture.AppendAuditDirectAsync(
            jobId, signedAt, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — beide Blobs sind nicht mehr abrufbar (AK-19, TC-38) …
        await using var scope = fixture.CreateScope();
        var portalDb = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        var verbleibende = await portalDb.Artifacts
            .Where(a => a.ArtifactId == originalId || a.ArtifactId == signaturId)
            .ToListAsync();
        Assert.Empty(verbleibende);
    }

    [Fact]
    public async Task ExecuteAsync_lässt_Audit_Bestand_unverändert_und_Kette_intakt()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var originalId = Guid.NewGuid();
        var signaturId = Guid.NewGuid();
        var signedAt = Jetzt.AddDays(-120);

        await fixture.SeedSignierteSagaAsync(jobId, originalId, signaturId, receivedAt: signedAt);
        await fixture.SeedArtifactsAsync(NeuesArtefakt(originalId), NeuesArtefakt(signaturId));
        await fixture.AppendAuditDirectAsync(
            jobId, signedAt.AddMinutes(-5), AuditCategories.Saga, "ScanLaeuft: Scan Clean — Auto-Signierung angefragt", "system:auto-sign", "score=5");
        await fixture.AppendAuditDirectAsync(
            jobId, signedAt, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — Scan-Ergebnis und Signier-Eintrag bleiben unverändert bestehen (REQ-19) …
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var eintraege = await auditDb.AuditEntries
            .Where(a => a.JobId == jobId)
            .OrderBy(a => a.Id)
            .ToListAsync();
        // … neben dem Retention-Lösch-Eintrag (REQ-18), der die Kette fortsetzt.
        Assert.Equal(3, eintraege.Count);
        var bestand = eintraege.Where(a => a.Category != AuditCategories.Deletion).ToList();
        Assert.Equal(2, bestand.Count);
        Assert.Contains(bestand, a => a.Ereignis.StartsWith("Signiert:", StringComparison.Ordinal));
        Assert.Contains(bestand, a => a.Ereignis.Contains("Scan Clean", StringComparison.Ordinal));
        // … und die globale Hash-Kette ist nach wie vor valide (AK-19, TC-38).
        Assert.True(AuditHashChain.Verify(eintraege, firstPrevHashExistsInTable: true).Valid);
    }

    [Fact]
    public async Task ExecuteAsync_protokolliert_Löschung_append_only_und_bleibt_idempotent()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var originalId = Guid.NewGuid();
        var signaturId = Guid.NewGuid();
        var signedAt = Jetzt.AddDays(-100);

        await fixture.SeedSignierteSagaAsync(jobId, originalId, signaturId, receivedAt: signedAt);
        await fixture.SeedArtifactsAsync(NeuesArtefakt(originalId), NeuesArtefakt(signaturId));
        await fixture.AppendAuditDirectAsync(
            jobId, signedAt, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service");

        fixture.Time.SetUtcNow(Jetzt);

        // Act — zwei Läufe (z. B. nach Neustart des WorkerService)
        await FühreRetentionAusAsync();
        await FühreRetentionAusAsync();

        // Assert — genau ein Lösch-Eintrag (REQ-18: Löschungen werden protokolliert) …
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var loeschEintraege = await auditDb.AuditEntries
            .Where(a => a.JobId == jobId && a.Category == AuditCategories.Deletion)
            .ToListAsync();
        Assert.Single(loeschEintraege);
        Assert.Equal("system:retention", loeschEintraege[0].Aktor);
        // … und die Kette bleibt auch nach dem zweiten Lauf intakt.
        var alle = await auditDb.AuditEntries
            .Where(a => a.JobId == jobId)
            .OrderBy(a => a.Id)
            .ToListAsync();
        Assert.True(AuditHashChain.Verify(alle, firstPrevHashExistsInTable: true).Valid);
    }

    [Fact]
    public async Task ExecuteAsync_innerhalb_der_Frist_bleiben_Blobs_unberührt()
    {
        // Arrange — Negative-Seite der Frist (REQ-19: erst nach 90 Tagen löschen)
        var jobId = Guid.NewGuid();
        var originalId = Guid.NewGuid();
        var signaturId = Guid.NewGuid();
        var signedAt = Jetzt.AddDays(-89);

        await fixture.SeedSignierteSagaAsync(jobId, originalId, signaturId, receivedAt: signedAt);
        await fixture.SeedArtifactsAsync(NeuesArtefakt(originalId), NeuesArtefakt(signaturId));
        await fixture.AppendAuditDirectAsync(
            jobId, signedAt, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert
        await using var scope = fixture.CreateScope();
        var portalDb = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        Assert.Equal(2, await portalDb.Artifacts.CountAsync());
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        Assert.Equal(
            0,
            await auditDb.AuditEntries.CountAsync(a => a.JobId == jobId && a.Category == AuditCategories.Deletion));
    }

    private async Task FühreRetentionAusAsync()
    {
        await using var scope = fixture.CreateScope();
        var executor = scope.ServiceProvider.GetRequiredService<RetentionExecutor>();
        await executor.ExecuteAsync(CancellationToken.None);
    }

    private static Artifact NeuesArtefakt(Guid artifactId) => new()
    {
        ArtifactId = artifactId,
        Content = [0x50, 0x4B, 0x03, 0x04],
        ContentSha256 = new string('a', 64),
    };
}
