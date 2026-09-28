using MassTransit;
using MassTransit.EntityFrameworkCoreIntegration;
using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WorkerService.Data;
using OfficeSelfSigningPortal.WorkerService.Messaging;
using OfficeSelfSigningPortal.WorkerService.Saga;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Messaging;

/// <summary>
/// Zentrale MassTransit-Verdrahtung der AnalysisSaga — dieselbe Registrierung und
/// Endpoint-Konfiguration laufen in Produktion (Program.cs), im InMemory-Seam S2
/// (Unit-Suite) und im RabbitMQ/PostgreSQL-Transport-Slice (Integrationstests).
/// </summary>
public static class AnalysisSagaBusConfiguration
{
    /// <summary>
    /// Registriert State Machine, Repository und Dead-Letter-Consumer.
    /// </summary>
    /// <param name="useEntityFrameworkRepository">
    /// true = EF-Core-Repository auf <see cref="WorkerDbContext"/> (pessimistische
    /// Sperren, Persistenz über Neustarts, REQ-11/TC-39); false = InMemory-Repository
    /// für den Harness-Seam S2.
    /// </param>
    public static void AddAnalysisSaga(this IBusRegistrationConfigurator configurator, bool useEntityFrameworkRepository)
    {
        if (useEntityFrameworkRepository)
        {
            configurator.AddSagaStateMachine<AnalysisSaga, AnalysisSagaState>()
                .EntityFrameworkRepository(r =>
                {
                    r.ExistingDbContext<WorkerDbContext>();
                    r.ConcurrencyMode = ConcurrencyMode.Pessimistic;
                    // Sperrsyntax explizit postgres (MassTransit-Default ist SQL Server
                    // "WITH (UPDLOCK, ROWLOCK)", was auf PostgreSQL fehlschlägt).
                    r.LockStatementProvider = new PostgresLockStatementProvider();
                });
        }
        else
        {
            configurator.AddSagaStateMachine<AnalysisSaga, AnalysisSagaState>().InMemoryRepository();
        }

        configurator.AddConsumer<ScanDeadLetterConsumer>();
        configurator.AddConsumer<ScanExecutionConsumer>();
    }

    /// <summary>
    /// Saga-Endpoint: Retry (exponentiell + Jitter) und EF-Core-Outbox — Publishes der
    /// Saga (z. B. SignMacroRequested, interne Ereignisse) committen atomar mit dem
    /// Zustandsübergang (REQ-11, TM-06).
    /// </summary>
    public static void ConfigureSagaEndpoint(
        IReceiveEndpointConfigurator endpoint,
        IBusRegistrationContext context,
        OsspRetryOptions retryOptions,
        bool useEntityFrameworkOutbox)
    {
        endpoint.UseMessageRetry(r => r.Intervals(
            OsspBusConventions.JitteredExponentialIntervals(retryOptions.Limit, retryOptions.MinDelay, retryOptions.MaxDelay)));

        if (useEntityFrameworkOutbox)
        {
            endpoint.UseEntityFrameworkOutbox<WorkerDbContext>(context);
        }

        endpoint.ConfigureSaga<AnalysisSagaState>(context);
    }

    /// <summary>
    /// Scanner-Ausführungs-Endpoint (Ticket 05): Retry (exponentiell + Jitter, REQ-22) —
    /// nach dem Limit verschiebt der Broker auf <c>ossp.scan-requested_error</c> (TC-16).
    /// Keine EF-Outbox nötig: Der Consumer hält keinen lokalen Zustand; das
    /// ScanCompleted-Publish ist selbst der fachliche Abschluss (Fehler → Fault → Retry → DLQ).
    /// </summary>
    public static void ConfigureScanExecutionEndpoint(
        IReceiveEndpointConfigurator endpoint,
        IBusRegistrationContext context,
        OsspRetryOptions retryOptions)
    {
        endpoint.UseMessageRetry(r => r.Intervals(
            OsspBusConventions.JitteredExponentialIntervals(retryOptions.Limit, retryOptions.MinDelay, retryOptions.MaxDelay)));
        endpoint.ConfigureConsumer<ScanExecutionConsumer>(context);
    }

    /// <summary>Dead-Letter-Endpoint der Scanner-Error-Queue (TC-16).</summary>
    public static void ConfigureScanDeadLetterEndpoint(
        IReceiveEndpointConfigurator endpoint,
        IBusRegistrationContext context)
    {
        // Nur Nachrichten, die MassTransit nach Retry-Exhaustion in die Error-Queue
        // VERSCHIEBT — kein Bindung auf die Message-Exchanges: sonst wäre der Bridge
        // ein konkurrierender Consumer der Live-Publishes und würde frische
        // ScanRequested sofort als "DLQ" behandeln (SagaNotFound-Fehlschläge).
        endpoint.ConfigureConsumeTopology = false;
        endpoint.ConfigureConsumer<ScanDeadLetterConsumer>(context);
    }
}
