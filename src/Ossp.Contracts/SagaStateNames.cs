namespace Ossp.Contracts;

/// <summary>
/// Verbindliche Saga-Zustandsbezeichner (Anhang B) — einzige Quelle für
/// Persistenz (Saga-Spalte <c>CurrentState</c>), SigningService-Guard (TM-19)
/// und Serialisierung. Die WebUI führt dieselbe Liste als <c>JobStatus</c>-Enum.
/// </summary>
public static class SagaStateNames
{
    public const string Eingereicht = nameof(Eingereicht);
    public const string InValidierung = nameof(InValidierung);
    public const string ScanLaeuft = nameof(ScanLaeuft);
    public const string ReviewAusstehend = nameof(ReviewAusstehend);
    public const string RueckfrageAusstehend = nameof(RueckfrageAusstehend);
    public const string SignierungAngefragt = nameof(SignierungAngefragt);
    public const string Signiert = nameof(Signiert);
    public const string Abgelehnt = nameof(Abgelehnt);
    public const string NichtSignierbar = nameof(NichtSignierbar);
    public const string Fehler = nameof(Fehler);

    /// <summary>Endzustände (Anhang B).</summary>
    public static readonly IReadOnlySet<string> EndStates = new HashSet<string>(StringComparer.Ordinal)
    {
        Signiert, Abgelehnt, NichtSignierbar, Fehler,
    };
}
