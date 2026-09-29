using Ossp.Audit;

namespace OfficeSelfSigningPortal.Tests.Audit;

/// <summary>
/// Einheits-Seam der Audit-Hash-Kette (TC-36/TC-37, AK-07/AK-18): Kanonisierung,
/// Verkettung und Manipulationserkennung ohne Datenbank.
/// </summary>
public sealed class AuditHashChainTests
{
    private static readonly DateTimeOffset FixedOccurredAt =
        new(2025, 9, 28, 12, 0, 0, TimeSpan.Zero);

    private static AuditEntry Eintrag(
        long id,
        Guid jobId,
        string ereignis,
        string aktor,
        string prevHash,
        string? detail = null,
        string category = AuditCategories.Saga)
    {
        var entry = new AuditEntry
        {
            Id = id,
            JobId = jobId,
            OccurredAt = FixedOccurredAt,
            Category = category,
            Ereignis = ereignis,
            Aktor = aktor,
            Detail = detail,
            PrevHash = prevHash,
        };
        entry.EntryHash = AuditHashChain.ComputeEntryHash(entry);
        return entry;
    }

    [Fact]
    public void ComputeEntryHash_ist_fuer_gleiche_felder_deterministisch()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var erste = Eintrag(1, jobId, "Eingereicht: Upload persistiert", "alice", AuditHashChain.GenesisPrevHash);
        var zweite = Eintrag(1, jobId, "Eingereicht: Upload persistiert", "alice", AuditHashChain.GenesisPrevHash);

        // Act
        var hashErste = AuditHashChain.ComputeEntryHash(erste);
        var hashZweite = AuditHashChain.ComputeEntryHash(zweite);

        // Assert
        Assert.Equal(hashErste, hashZweite);
        Assert.Equal(64, hashErste.Length);
    }

    [Fact]
    public void ComputeEntryHash_aendert_sich_bei_jeder_feldmanipulation()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var basis = Eintrag(1, jobId, "Scan Clean — Auto-Signierung", "system:auto-sign", AuditHashChain.GenesisPrevHash, detail: "score=5");
        var originellerHash = basis.EntryHash;

        // Act — einzelne Felder nachträglich verändern (Angriffsszenario TC-37)
        basis.Ereignis = "Scan Malicious — abgelehnt";
        var hashNachEreignis = AuditHashChain.ComputeEntryHash(basis);
        basis.Ereignis = "Scan Clean — Auto-Signierung";
        basis.Aktor = "mallory";
        var hashNachAktor = AuditHashChain.ComputeEntryHash(basis);
        basis.Aktor = "system:auto-sign";
        basis.Detail = "score=99";
        var hashNachDetail = AuditHashChain.ComputeEntryHash(basis);

        // Assert
        Assert.NotEqual(originellerHash, hashNachEreignis);
        Assert.NotEqual(originellerHash, hashNachAktor);
        Assert.NotEqual(originellerHash, hashNachDetail);
    }

    [Fact]
    public void Verify_leere_ereignisliste_ist_valide()
    {
        // Arrange
        IReadOnlyList<AuditEntry> eintraege = [];

        // Act
        var ergebnis = AuditHashChain.Verify(eintraege, firstPrevHashExistsInTable: false);

        // Assert
        Assert.True(ergebnis.Valid);
        Assert.Equal(0, ergebnis.EntriesChecked);
    }

    [Fact]
    public void Verify_valide_kette_mit_genesis_als_erstem_glied()
    {
        // Arrange
        var jobId = Guid.NewGuid();
        var erste = Eintrag(1, jobId, "Eingereicht: Upload persistiert", "alice", AuditHashChain.GenesisPrevHash);
        var zweite = Eintrag(2, jobId, "ScanLaeuft: Scan startet", "system:saga", erste.EntryHash);
        var dritte = Eintrag(3, jobId, "Signiert: Signierung abgeschlossen", "system:signing-service", zweite.EntryHash);

        // Act
        var ergebnis = AuditHashChain.Verify([erste, zweite, dritte], firstPrevHashExistsInTable: false);

        // Assert
        Assert.True(ergebnis.Valid);
        Assert.Equal(3, ergebnis.EntriesChecked);
        Assert.Null(ergebnis.BrokenAtEntryId);
    }

    [Fact]
    public void Verify_erkennt_manipulierten_eintrag()
    {
        // Arrange — Detail nachträglich in der "Datenbank" geändert, Hash unverändert (TC-37)
        var jobId = Guid.NewGuid();
        var erste = Eintrag(1, jobId, "Eingereicht: Upload persistiert", "alice", AuditHashChain.GenesisPrevHash);
        var zweite = Eintrag(2, jobId, "Scan Clean — Auto-Signierung", "system:auto-sign", erste.EntryHash, detail: "score=5");
        zweite.Detail = "score=5, manipuliert";

        // Act
        var ergebnis = AuditHashChain.Verify([erste, zweite], firstPrevHashExistsInTable: false);

        // Assert
        Assert.False(ergebnis.Valid);
        Assert.Equal(zweite.Id, ergebnis.BrokenAtEntryId);
    }

    [Fact]
    public void Verify_erkennt_unterbrochenes_kettenglied_durch_geloeschten_eintrag()
    {
        // Arrange — mittlerer Eintrag direkt gelöscht: Nachfolger zeigt auf fehlenden Hash (TC-37)
        var jobId = Guid.NewGuid();
        var erste = Eintrag(1, jobId, "Eingereicht: Upload persistiert", "alice", AuditHashChain.GenesisPrevHash);
        var zweite = Eintrag(2, jobId, "ReviewAusstehend: Review-Pflicht", "system:saga", erste.EntryHash);
        var dritte = Eintrag(3, jobId, "Abgelehnt: Review-Ablehnung", "bob", zweite.EntryHash);

        // Act — nur erste und dritte geladen (zweite wurde "gelöscht")
        var ergebnis = AuditHashChain.Verify([erste, dritte], firstPrevHashExistsInTable: false);

        // Assert
        Assert.False(ergebnis.Valid);
        Assert.Equal(dritte.Id, ergebnis.BrokenAtEntryId);
    }

    [Fact]
    public void Verify_erkennt_fehlenden_vorgaenger_ausserhalb_des_vorgangs()
    {
        // Arrange — erster geladener Eintrag verweist auf einen Hash, der in der Tabelle nicht existiert
        var jobId = Guid.NewGuid();
        var erste = Eintrag(10, jobId, "ScanLaeuft: Scan startet", "system:saga",
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("fremd"u8)).ToLowerInvariant());

        // Act
        var ergebnis = AuditHashChain.Verify([erste], firstPrevHashExistsInTable: false);

        // Assert
        Assert.False(ergebnis.Valid);
        Assert.Equal(erste.Id, ergebnis.BrokenAtEntryId);
    }

    [Fact]
    public void Verify_akzeptiert_echten_vorgaenger_ausserhalb_des_vorgangs()
    {
        // Arrange — global verkettete Tabelle: Der Vorgänger des ersten Vorgangs-Eintrags
        // gehört zu einem anderen Vorgang und ist in der Tabelle vorhanden.
        var jobId = Guid.NewGuid();
        var fremderVorgaenger = Eintrag(9, Guid.NewGuid(), "upload: Upload persistiert", "carol", AuditHashChain.GenesisPrevHash);
        var erste = Eintrag(10, jobId, "saga: Scan startet", "system:saga", fremderVorgaenger.EntryHash);

        // Act
        var ergebnis = AuditHashChain.Verify([erste], firstPrevHashExistsInTable: true);

        // Assert
        Assert.True(ergebnis.Valid);
        Assert.Equal(1, ergebnis.EntriesChecked);
    }
}
