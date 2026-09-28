using Microsoft.EntityFrameworkCore;
using Npgsql;
using Ossp.Audit;
using Xunit;

namespace OfficeSelfSigningPortal.Tests.Audit;

/// <summary>
/// Seam S5 — Audit-Trail auf Testcontainers-PostgreSQL (TC-36/TC-37, AK-07/AK-18,
/// REQ-18): append-only Schreibpfad mit globaler SHA-256-Hash-Kette, Serialisierung
/// paralleler Writer und Erkennung direkter DB-Manipulation.
/// </summary>
[Trait("Category", "Integration")]
[Collection(AuditS5Collection.CollectionName)]
public sealed class AuditTrailS5Tests(AuditS5Fixture fixture)
{
    [Fact]
    public async Task AppendAsync_schreibt_eintrag_verkettet_an_den_aktuellen_tabellenkopf()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var kopfVorher = await LetzterEntryHashOderGenesisAsync();

        // Act
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Upload, "Upload persistiert", "alice", "doku.xlsm", CancellationToken.None);

        // Assert
        await using var db = fixture.CreateAuditDbContext();
        var eintrag = await db.AuditEntries.SingleAsync(a => a.JobId == jobId);
        Assert.Equal(kopfVorher, eintrag.PrevHash);
        Assert.Equal(AuditHashChain.ComputeEntryHash(eintrag), eintrag.EntryHash);
    }

    [Fact]
    public async Task AppendAsync_verkettet_folgeeintraege_mit_sha256_des_vorgaengers()
    {
        // Arrange — TC-36: mehrere Ereignisse eines Vorgangs landen in zeitlicher Reihenfolge
        var jobId = Guid.NewGuid();

        // Act
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Upload, "Upload persistiert", "alice", "doku.xlsm", CancellationToken.None);
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Saga, "ScanLaeuft: Scan startet", "system:saga", null, CancellationToken.None);
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service", null, CancellationToken.None);

        // Assert
        await using var db = fixture.CreateAuditDbContext();
        var eintraege = await db.AuditEntries.Where(a => a.JobId == jobId).OrderBy(a => a.Id).ToListAsync();
        Assert.Equal(3, eintraege.Count);
        // Der erste Eintrag des Vorgangs hängt am globalen Tabellenkopf — dessen Hash
        // existiert in der Tabelle (oder ist Genesis bei leerer Tabelle).
        Assert.True(AuditHashChain.Verify(eintraege, firstPrevHashExistsInTable: true).Valid);
    }

    [Fact]
    public async Task AppendAsync_ParalleleWriter_bleiben_serialisiert_und_kette_bleibt_valide()
    {
        // Arrange — parallele Services (WebUI/Worker/Signing) schreiben über denselben
        // Append-Pfad; die Hash-Kette darf durch Concurrent Appends nicht brechen.
        // Das Fenster der eigenen Appends wird hermetisch geprüft (Vorher-Stand merken).
        var jobA = Guid.NewGuid();
        var jobB = Guid.NewGuid();
        var fensterKopf = await LetzterEntryHashOderGenesisAsync();
        var fensterStartId = await LetzteIdOderNullAsync();

        // Act
        var appends = Enumerable.Range(0, 12)
            .Select(i => fixture.Writer.AppendAsync(
                i % 2 == 0 ? jobA : jobB,
                AuditCategories.Saga,
                $"Ereignis {i}",
                "system:saga",
                detail: null,
                CancellationToken.None))
            .ToArray();
        await Task.WhenAll(appends);

        // Assert — die eigenen 12 Einträge bilden ein lückenlos verkettetes Fenster
        await using var db = fixture.CreateAuditDbContext();
        var fenster = await db.AuditEntries.AsNoTracking()
            .Where(a => fensterStartId == null || a.Id > fensterStartId)
            .OrderBy(a => a.Id)
            .ToListAsync();
        Assert.Equal(12, fenster.Count);
        Assert.Equal(fensterKopf, fenster[0].PrevHash);
        for (var i = 0; i < fenster.Count; i++)
        {
            Assert.Equal(AuditHashChain.ComputeEntryHash(fenster[i]), fenster[i].EntryHash);
            if (i > 0)
            {
                Assert.Equal(fenster[i - 1].EntryHash, fenster[i].PrevHash);
            }
        }
    }

    [Fact]
    public async Task Verify_erkennt_direkte_DB_Manipulation_eines_eintrags()
    {
        // Arrange — TC-37/AK-18: Angreifer mit DB-Zugriff ändert einen Eintrag direkt
        var jobId = Guid.NewGuid();
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Saga, "Scan Clean — Auto-Signierung", "system:auto-sign", "score=5", CancellationToken.None);
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Saga, "Signiert: Signierung abgeschlossen", "system:signing-service", null, CancellationToken.None);

        // Act — Manipulation außerhalb der Anwendung (kein EF-Pfad)
        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE audit_trail SET \"Detail\" = 'score=5, unauffaellig' WHERE \"JobId\" = @jobId AND \"Detail\" = 'score=5'",
                connection);
            command.Parameters.AddWithValue("jobId", jobId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        // Assert — Ketten-Prüfung beim Admin-Abruf schlägt fehl
        await using var db = fixture.CreateAuditDbContext();
        var eintraege = await db.AuditEntries.Where(a => a.JobId == jobId).OrderBy(a => a.Id).ToListAsync();
        var ergebnis = AuditHashChain.Verify(eintraege, firstPrevHashExistsInTable: true);
        Assert.False(ergebnis.Valid);
        Assert.NotNull(ergebnis.BrokenAtEntryId);
    }

    [Fact]
    public async Task Verify_erkennt_direktes_DB_Loeschen_eines_eintrags()
    {
        // Arrange — TC-37/AK-18: Löschung eines mittleren Eintrags reißt das Kettenglied
        var jobId = Guid.NewGuid();
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Upload, "Upload persistiert", "alice", "doku.xlsm", CancellationToken.None);
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Saga, "ReviewAusstehend: Review-Pflicht", "system:saga", null, CancellationToken.None);
        await fixture.Writer.AppendAsync(jobId, AuditCategories.Saga, "Abgelehnt: Review-Ablehnung", "bob", null, CancellationToken.None);

        // Act
        await using (var connection = new NpgsqlConnection(fixture.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "DELETE FROM audit_trail WHERE \"JobId\" = @jobId AND \"Ereignis\" LIKE 'ReviewAusstehend%'",
                connection);
            command.Parameters.AddWithValue("jobId", jobId);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        // Assert
        await using var db = fixture.CreateAuditDbContext();
        var eintraege = await db.AuditEntries.Where(a => a.JobId == jobId).OrderBy(a => a.Id).ToListAsync();
        Assert.False(AuditHashChain.Verify(eintraege, firstPrevHashExistsInTable: true).Valid);
    }

    private async Task<string> LetzterEntryHashOderGenesisAsync()
    {
        await using var db = fixture.CreateAuditDbContext();
        return await db.AuditEntries.OrderByDescending(a => a.Id).Select(a => a.EntryHash).FirstOrDefaultAsync()
            ?? AuditHashChain.GenesisPrevHash;
    }

    private async Task<long?> LetzteIdOderNullAsync()
    {
        await using var db = fixture.CreateAuditDbContext();
        return await db.AuditEntries.OrderByDescending(a => a.Id).Select(a => (long?)a.Id).FirstOrDefaultAsync();
    }
}
