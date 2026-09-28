namespace Ossp.Contracts;

/// <summary>
/// Retry-Policy-Parameter der Bus-Endpunkte (REQ-22, TM-16) — geteilter
/// Konfigurationsabschnitt <see cref="SectionName"/> (Betriebskonvention,
/// kein Nachrichtenvertrag). Werte: exponentieller Backoff + Jitter via
/// <see cref="OsspBusConventions"/>; nach dem Limit landet die Nachricht im
/// Dead-Letter-Pfad.
/// </summary>
public sealed class OsspRetryOptions
{
    public const string SectionName = "OsspRetry";

    public int Limit { get; set; } = 5;

    public TimeSpan MinDelay { get; set; } = TimeSpan.FromSeconds(1);

    public TimeSpan MaxDelay { get; set; } = TimeSpan.FromMinutes(2);
}
