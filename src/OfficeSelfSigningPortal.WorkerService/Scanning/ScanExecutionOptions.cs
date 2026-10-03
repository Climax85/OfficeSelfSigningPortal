namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Konfiguration der Scan-Ausführungs-Stage am MassTransit-Endpoint
/// (Abschnitt <see cref="SectionName"/>): ConcurrencyLimit und PrefetchCount
/// (TM-14, SF-03). Die Werte begrenzen, wie viele <see cref="Messaging.ScanExecutionConsumer"/>-
/// Instanzen gleichzeitig Nachrichten vom RabbitMQ-Pull beziehen und verarbeiten
/// — Backpressure gegen Queue-Überlastung durch Flooding.
/// </summary>
public sealed class ScanExecutionOptions
{
    public const string SectionName = "Scanning:Execution";

    /// <summary>
    /// Maximal gleichzeitig verarbeitete Scan-Aufträge (MassTransit
    /// <c>UseConcurrencyLimit</c>, TM-14). Niedrigere Werte schonen Scanner-
    /// Ressourcen (CPU/RAM, clamd-Verbindungen); zu hohe Werte laden die
    /// Pipeline-Worker voll und können den Broker in den Prefetch-Sättigen.
    /// </summary>
    public int MaxConcurrentMessages { get; set; } = 4;

    /// <summary>
    /// MassTransit <c>PrefetchCount</c>: wie viele Nachrichten der Consumer
    /// vorausschauend vom Broker holt. Sollte >= <see cref="MaxConcurrentMessages"/>
    /// sein, sonst bremst der Consumer sich selbst aus. Konservativ gleich
    /// <see cref="MaxConcurrentMessages"/> (kein Überschuss-Puffer im Dev-/Baseline-Profil).
    /// </summary>
    public int PrefetchCount { get; set; } = 4;
}
