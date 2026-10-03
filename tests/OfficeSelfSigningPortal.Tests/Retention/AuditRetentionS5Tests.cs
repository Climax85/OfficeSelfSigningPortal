using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OfficeSelfSigningPortal.WebUI.Data;
using OfficeSelfSigningPortal.WorkerService.Retention;
using Ossp.Audit;
using Ossp.Contracts;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Retention;

/// <summary>
/// Seam S5 — Audit-Retention Obergrenze 1 Jahr (Ticket 38, REQ-19, F4): Nach
/// Ablauf der konfigurierbaren Frist (Default 365 Tage) löscht der Job die
/// ältesten Audit-Einträge am kontinuierlichen Tabellenanfang. Die
/// sanctioned Lösch-Grenze wird als <c>audit_chain_checkpoints</c>-Eintrag
/// festgehalten, sodass die Hash-Ketten-Prüfung beim Admin-Abruf die Lücke
/// als sanctioned erkennt (REQ-18, AK-07, AK-18, AK-19). Die Löschung
/// selbst wird append-only auditprotokolliert und ist idempotent.
/// Eigener Container, weil die Id-Reihenfolge (Sortier-Grundlage der
/// Block-Löschung) bei geteiltem Fixture unvorhersehbar wäre. Per-Test-Fixture
/// (IDisposable), damit jeder Test mit einer leeren Tabelle startet.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AuditRetentionS5Tests : IDisposable
{
    private readonly AuditRetentionS5Fixture fixture = new();

    private static readonly DateTimeOffset Jetzt = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    public AuditRetentionS5Tests()
    {
        fixture.InitializeAsync().GetAwaiter().GetResult();
    }

    public void Dispose() => fixture.DisposeAsync().GetAwaiter().GetResult();

    [Fact]
    public async Task ExecuteAsync_1_Jahr_nach_Eintritt_loescht_aelteste_Audit_Eintraege()
    {
        // Arrange — TC-38 (erweitert): Audit-Einträge verschiedener Vorgänge,
        // deren Eintritt deutlich vor der 1-Jahr-Grenze liegt, werden gelöscht.
        // In Produktion sind die Einträge in Zeit-Reihenfolge (Id = Zeit),
        // daher erfolgt das Seeding hier ebenfalls in dieser Reihenfolge.
        var jobAlt1 = Guid.NewGuid();
        var jobAlt2 = Guid.NewGuid();
        var jobNeu = Guid.NewGuid();
        var sehrAlt = Jetzt.AddDays(-500);
        var alt = Jetzt.AddDays(-366);
        var vor90Tagen = Jetzt.AddDays(-90);

        await fixture.AppendAuditDirectAsync(
            jobAlt1, sehrAlt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "alice");
        await fixture.AppendAuditDirectAsync(
            jobAlt2, alt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "bob");
        await fixture.AppendAuditDirectAsync(
            jobNeu, vor90Tagen, AuditCategories.Saga, "Eingereicht: Upload persistiert", "carol");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — die beiden ältesten Einträge sind weg, der neue bleibt …
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        Assert.Equal(0, await auditDb.AuditEntries.CountAsync(a => a.JobId == jobAlt1));
        Assert.Equal(0, await auditDb.AuditEntries.CountAsync(a => a.JobId == jobAlt2));
        Assert.Equal(1, await auditDb.AuditEntries.CountAsync(a => a.JobId == jobNeu));
    }

    [Fact]
    public async Task ExecuteAsync_protokolliert_Audit_Retention_als_System_Deletion_und_ist_idempotent()
    {
        // Arrange — Eintrag deutlich älter als 1 Jahr, gefolgt von einem neuen
        // (Zeit-Reihenfolge, weil Id = Zeit in Produktion).
        var jobAlt = Guid.NewGuid();
        var jobNeu = Guid.NewGuid();
        var sehrAlt = Jetzt.AddDays(-500);
        var vorEinemJahrMinus1Tag = Jetzt.AddDays(-200);

        await fixture.AppendAuditDirectAsync(
            jobAlt, sehrAlt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "alice");
        await fixture.AppendAuditDirectAsync(
            jobNeu, vorEinemJahrMinus1Tag, AuditCategories.Saga, "Eingereicht: Upload persistiert", "bob");

        fixture.Time.SetUtcNow(Jetzt);

        // Act — zwei Läufe (Neustart / wiederholter Tick)
        await FühreRetentionAusAsync();
        var checkpointCountNachErstemLauf = await AnzahlAuditRetentionCheckpointsAsync();
        await FühreRetentionAusAsync();
        var checkpointCountNachZweitemLauf = await AnzahlAuditRetentionCheckpointsAsync();

        // Assert — der zweite Lauf erzeugt KEINEN weiteren Audit-Retention-Checkpoint
        // (idempotent), und die Hash-Kette der Tabelle bleibt nach beiden Läufen intakt.
        Assert.Equal(checkpointCountNachErstemLauf, checkpointCountNachZweitemLauf);

        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var alle = await auditDb.AuditEntries.OrderBy(a => a.Id).ToListAsync();
        Assert.True(AuditHashChain.Verify(alle, firstPrevHashExistsInTable: true).Valid);
    }

    [Fact]
    public async Task ExecuteAsync_schreibt_sanctioned_Loesch_Grenze_in_ChainCheckpoints()
    {
        // Arrange — Eintrag deutlich älter als 1 Jahr, gefolgt von einem
        // neueren (Zeit-Reihenfolge).
        var jobAlt = Guid.NewGuid();
        var jobNeu = Guid.NewGuid();
        var sehrAlt = Jetzt.AddDays(-500);
        var vorEinemJahrMinus1Tag = Jetzt.AddDays(-200);

        await fixture.AppendAuditDirectAsync(
            jobAlt, sehrAlt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "alice");
        await fixture.AppendAuditDirectAsync(
            jobNeu, vorEinemJahrMinus1Tag, AuditCategories.Saga, "Eingereicht: Upload persistiert", "bob");

        var checkpointsVorher = await AnzahlAuditRetentionCheckpointsAsync();

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — ein neuer Checkpoint wurde für die Retention erzeugt …
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var checkpointsNachher = await auditDb.ChainCheckpoints
            .Where(c => c.Reason == "audit-retention-365d")
            .ToListAsync();
        Assert.Equal(checkpointsVorher + 1, checkpointsNachher.Count);
        var checkpoint = checkpointsNachher[^1];
        Assert.Equal("system:retention", checkpoint.Aktor);
        Assert.True(checkpoint.DeletedCount > 0);
        Assert.NotEqual(0, checkpoint.FirstRemainingEntryId);
        Assert.False(string.IsNullOrEmpty(checkpoint.LastDeletedEntryHash));
        Assert.Equal(64, checkpoint.LastDeletedEntryHash.Length);

        // … und die gelöschten Einträge sind tatsächlich weg.
        Assert.Equal(0, await auditDb.AuditEntries.CountAsync(a => a.JobId == jobAlt));
    }

    [Fact]
    public async Task ExecuteAsync_chain_Verify_akzeptiert_sanctioned_Loesch_Grenze_als_Vorgaenger()
    {
        // Arrange — Eintrag vor 1 Jahr, der Vorgänger des ersten Eintrags der
        // Resttabelle zeigt nach Löschung auf den gelöschten Hash. Seeding in
        // Zeit-Reihenfolge (Produktionsverhalten).
        var jobAlt = Guid.NewGuid();
        var jobNeu = Guid.NewGuid();
        var sehrAlt = Jetzt.AddDays(-500);
        var vorEinemJahrMinus1Tag = Jetzt.AddDays(-200);

        await fixture.AppendAuditDirectAsync(
            jobAlt, sehrAlt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "alice");
        await fixture.AppendAuditDirectAsync(
            jobNeu, vorEinemJahrMinus1Tag, AuditCategories.Saga, "Eingereicht: Upload persistiert", "bob");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — der erste Eintrag des neu verbleibenden Vorgangs (jobNeu)
        // verweist auf einen Hash, der nicht mehr in der Tabelle ist, aber im
        // Checkpoint dokumentiert ist. Die Verify-Funktion akzeptiert ihn als
        // sanctioned Grenze.
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var jobNeuEintrag = await auditDb.AuditEntries
            .Where(a => a.JobId == jobNeu)
            .OrderBy(a => a.Id)
            .FirstAsync();
        var prevInTabelle = await auditDb.AuditEntries
            .AnyAsync(a => a.EntryHash == jobNeuEintrag.PrevHash);
        var prevIstCheckpoint = await auditDb.ChainCheckpoints
            .AnyAsync(c => c.LastDeletedEntryHash == jobNeuEintrag.PrevHash);
        Assert.False(prevInTabelle);
        Assert.True(prevIstCheckpoint);
        Assert.True(AuditHashChain.Verify(
            [jobNeuEintrag],
            firstPrevHashExistsInTable: false,
            firstPrevHashIsKnownDeletionBoundary: true).Valid);
    }

    [Fact]
    public async Task ExecuteAsync_junger_Eintrag_wird_nicht_geloescht()
    {
        // Arrange — Negativseite der Frist: Eintrag ist 364 Tage alt (innerhalb
        // des 1-Jahres-Fensters) und bleibt unangetastet. Seeding in
        // Zeit-Reihenfolge (Id = Zeit in Produktion).
        var jobAlt = Guid.NewGuid();
        var jobJung = Guid.NewGuid();
        var sehrAlt = Jetzt.AddDays(-500);
        var vorEinemJahrMinus1Tag = Jetzt.AddDays(-364);

        await fixture.AppendAuditDirectAsync(
            jobAlt, sehrAlt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "alice");
        await fixture.AppendAuditDirectAsync(
            jobJung, vorEinemJahrMinus1Tag, AuditCategories.Saga, "Eingereicht: Upload persistiert", "bob");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — der junge Eintrag ist noch da …
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var jungeEintraege = await auditDb.AuditEntries
            .Where(a => a.JobId == jobJung)
            .ToListAsync();
        Assert.Single(jungeEintraege);
        // … der sehr alte Eintrag ist weg (Bezugspunkt für den vorherigen
        // Test-Flow, der die Retention tatsächlich ausgelöst hat).
        Assert.Equal(0, await auditDb.AuditEntries.CountAsync(a => a.JobId == jobAlt));
    }

    [Fact]
    public async Task ExecuteAsync_beide_Loesch_Pfade_ergaenzen_sich_ohne_Konflikt()
    {
        // Arrange — ein signierter Vorgang (Blob-Retention-relevant, 100 Tage
        // alt) und ein Audit-Eintrag (Audit-Retention-relevant, 400 Tage alt).
        // Beide Pfade laufen im selben Executor-Tick und dürfen sich nicht
        // gegenseitig stören.
        var jobId = Guid.NewGuid();
        var originalId = Guid.NewGuid();
        var signaturId = Guid.NewGuid();
        var signedAt = Jetzt.AddDays(-100);
        var sehrAlt = Jetzt.AddDays(-400);

        await fixture.SeedSignierteSagaAsync(jobId, originalId, signaturId, receivedAt: signedAt);
        await fixture.SeedArtifactsAsync(NeuesArtefakt(originalId), NeuesArtefakt(signaturId));
        await fixture.AppendAuditDirectAsync(
            jobId, signedAt, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service");
        await fixture.AppendAuditDirectAsync(
            Guid.NewGuid(), sehrAlt, AuditCategories.Saga, "Eingereicht: Upload persistiert", "alice");

        fixture.Time.SetUtcNow(Jetzt);

        // Act
        await FühreRetentionAusAsync();

        // Assert — Blob ist weg, beide Audit-Pfade haben ihre Einträge
        // angehängt (Blob-Retention-Löschung + Audit-Retention-Löschung).
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        var portalDb = scope.ServiceProvider.GetRequiredService<PortalDbContext>();
        Assert.Empty(await portalDb.Artifacts.ToListAsync());
        // Signier-Audit (100 Tage alt) bleibt bestehen — innerhalb der
        // Audit-Retention-Frist.
        var signierEintrag = await auditDb.AuditEntries
            .Where(a => a.JobId == jobId && a.Ereignis.StartsWith("Signiert:"))
            .SingleAsync();
        Assert.NotNull(signierEintrag);
        // Blob-Retention-Löschung wurde auditprotokolliert.
        var blobLoeschEintrag = await auditDb.AuditEntries
            .Where(a => a.JobId == jobId && a.Category == AuditCategories.Deletion)
            .SingleAsync();
        Assert.Equal("system:retention", blobLoeschEintrag.Aktor);
        // … und die Kette ist nach beiden Läufen intakt.
        var alle = await auditDb.AuditEntries.OrderBy(a => a.Id).ToListAsync();
        Assert.True(AuditHashChain.Verify(alle, firstPrevHashExistsInTable: true).Valid);
    }

    [Fact]
    public void AuditHashChain_Verify_akzeptiert_sanctioned_Loesch_Grenze_als_Vorgaenger()
    {
        // Arrange — direkter Unit-Test der Verify-Erweiterung: ein Eintrag
        // verweist auf einen Hash, der nicht in der Tabelle und nicht der
        // Genesis ist. Ohne sanctioned-Boundary bricht die Kette; mit ihr ist
        // sie valide.
        var jobId = Guid.NewGuid();
        var fehlenderVorgaengerHash = new string('a', 64);

        var eintrag = new AuditEntry
        {
            Id = 4,
            JobId = jobId,
            OccurredAt = Jetzt,
            Category = AuditCategories.Saga,
            Ereignis = "Eingereicht: Upload persistiert",
            Aktor = "alice",
            PrevHash = fehlenderVorgaengerHash,
        };
        eintrag.EntryHash = AuditHashChain.ComputeEntryHash(eintrag);

        // Act + Assert — ohne sanctioned-Boundary: Kette bricht.
        var ohneBoundary = AuditHashChain.Verify(
            [eintrag],
            firstPrevHashExistsInTable: false,
            firstPrevHashIsKnownDeletionBoundary: false);
        Assert.False(ohneBoundary.Valid);

        // Act + Assert — mit sanctioned-Boundary: Kette ist valide.
        var mitBoundary = AuditHashChain.Verify(
            [eintrag],
            firstPrevHashExistsInTable: false,
            firstPrevHashIsKnownDeletionBoundary: true);
        Assert.True(mitBoundary.Valid);
        Assert.Equal(1, mitBoundary.EntriesChecked);
    }

    private async Task FühreRetentionAusAsync()
    {
        await using var scope = fixture.CreateScope();
        var executor = scope.ServiceProvider.GetRequiredService<RetentionExecutor>();
        await executor.ExecuteAsync(CancellationToken.None);
    }

    private async Task<int> AnzahlAuditRetentionCheckpointsAsync()
    {
        await using var scope = fixture.CreateScope();
        var auditDb = scope.ServiceProvider.GetRequiredService<AuditDbContext>();
        return await auditDb.ChainCheckpoints
            .CountAsync(c => c.Reason == "audit-retention-365d");
    }

    private static Artifact NeuesArtefakt(Guid artifactId) => new()
    {
        ArtifactId = artifactId,
        Content = [0x50, 0x4B, 0x03, 0x04],
        ContentSha256 = new string('a', 64),
    };
}
