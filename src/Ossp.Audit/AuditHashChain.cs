using System.Globalization;
using System.Text;

namespace Ossp.Audit;

/// <summary>Ergebnis der Hash-Ketten-Prüfung beim Admin-Abruf (AK-07, AK-18).</summary>
/// <param name="Valid">True, wenn alle geladenen Einträge lückenlos verkettet und unverändert sind.</param>
/// <param name="EntriesChecked">Anzahl geprüfter Einträge.</param>
/// <param name="BrokenAtEntryId">Id des Eintrags, an dem die Kette bricht (null bei valider Kette).</param>
/// <param name="Detail">Fachliche Beschreibung des Bruchs für den Admin/Prüfer.</param>
public sealed record AuditChainVerificationResult(
    bool Valid,
    int EntriesChecked,
    long? BrokenAtEntryId,
    string? Detail);

/// <summary>
/// SHA-256-Hash-Kette des Audit-Trails (REQ-18, TM-04): Jeder Eintrag verkettet den
/// Hash seines Vorgängers; die Prüfung läuft beim Admin-Abruf. Die Kette ist global
/// über die Tabelle — der Admin-Abruf prüft die Einträge eines Vorgangs und
/// verifiziert den Vorgänger des ersten Eintrags gegen die Tabelle (Lücken- und
/// Manipulationserkennung, TC-36/TC-37).
/// </summary>
public static class AuditHashChain
{
    /// <summary>PrevHash des aller ersten Tabelleneintrags: 64 hex-Nullen.</summary>
    public const string GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// Kanonischer Eintragshash: SHA-256 über längenpräfixierte Felder (UTF-8, hex klein).
    /// Die Längenpräfixe verhindern Feldgrenz-Ambiguitäten (z. B. "ab"+"c" vs. "a"+"bc").
    /// Die Id ist bewusst kein Hash-Bestandteil: Sie wird erst beim Insert von der
    /// Datenbank vergeben (Hash-Berechnung läuft davor). Reihenfolge und Lücken
    /// sichert die Verkettung über <see cref="AuditEntry.PrevHash"/>. Der Zeitstempel
    /// wird auf Mikrosekunden normalisiert — genau die Präzision, mit der PostgreSQL
    /// <c>timestamptz</c> round-tript; sonst wäre jeder Re-Hash nach dem Reload
    /// fälschlich "manipuliert" (TC-37-Fehlalarm).
    /// </summary>
    public static string ComputeEntryHash(AuditEntry entry)
    {
        var builder = new StringBuilder(capacity: 256);
        AppendFeld(builder, (entry.OccurredAt.UtcDateTime.Ticks / 10).ToString(CultureInfo.InvariantCulture));
        AppendFeld(builder, entry.JobId.ToString("N"));
        AppendFeld(builder, entry.Category);
        AppendFeld(builder, entry.Ereignis);
        AppendFeld(builder, entry.Aktor);
        AppendFeld(builder, entry.Detail ?? string.Empty);
        AppendFeld(builder, entry.PrevHash);

        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString()));
        return Convert.ToHexString(hash).ToLowerInvariant();

        static void AppendFeld(StringBuilder builder, string value)
            => builder.Append(value.Length).Append(':').Append(value);
    }

    /// <summary>
    /// Prüft die (nach Id sortierten) Einträge eines Vorgangs. Der erste Eintrag muss
    /// entweder Genesis-Vorgänger haben, auf einen Hash verweisen, der mit
    /// <paramref name="firstPrevHashExistsInTable"/> als in der Tabelle vorhanden bestätigt wird,
    /// oder eine sanctioned Lösch-Grenze der Audit-Retention sein
    /// (<paramref name="firstPrevHashIsKnownDeletionBoundary"/>, REQ-19, Ticket 38).
    /// </summary>
    public static AuditChainVerificationResult Verify(
        IReadOnlyList<AuditEntry> jobEntries,
        bool firstPrevHashExistsInTable,
        bool firstPrevHashIsKnownDeletionBoundary = false)
    {
        if (jobEntries.Count == 0)
        {
            return new AuditChainVerificationResult(Valid: true, EntriesChecked: 0, BrokenAtEntryId: null, Detail: null);
        }

        var erster = jobEntries[0];
        if (!GenesisPrevHash.Equals(erster.PrevHash, StringComparison.Ordinal)
            && !firstPrevHashExistsInTable
            && !firstPrevHashIsKnownDeletionBoundary)
        {
            return new AuditChainVerificationResult(
                Valid: false,
                EntriesChecked: 0,
                BrokenAtEntryId: erster.Id,
                Detail: $"Vorgänger-Hash des ersten Eintrags ({erster.PrevHash}) ist in der Audit-Tabelle nicht auffindbar — möglicherweise wurden Einträge gelöscht.");
        }

        for (var i = 0; i < jobEntries.Count; i++)
        {
            var eintrag = jobEntries[i];
            if (!ComputeEntryHash(eintrag).Equals(eintrag.EntryHash, StringComparison.Ordinal))
            {
                return new AuditChainVerificationResult(
                    Valid: false,
                    EntriesChecked: i,
                    BrokenAtEntryId: eintrag.Id,
                    Detail: "Eintrags-Hash stimmt nicht mit den gespeicherten Feldern überein — möglicherweise wurde der Eintrag direkt in der Datenbank verändert.");
            }

            if (i > 0 && !eintrag.PrevHash.Equals(jobEntries[i - 1].EntryHash, StringComparison.Ordinal))
            {
                return new AuditChainVerificationResult(
                    Valid: false,
                    EntriesChecked: i,
                    BrokenAtEntryId: eintrag.Id,
                    Detail: "Kettenglied unterbrochen: Vorgänger-Hash passt nicht zum vorherigen Eintrag — möglicherweise wurde ein Eintrag gelöscht oder die Reihenfolge verändert.");
            }
        }

        return new AuditChainVerificationResult(Valid: true, EntriesChecked: jobEntries.Count, BrokenAtEntryId: null, Detail: null);
    }
}
