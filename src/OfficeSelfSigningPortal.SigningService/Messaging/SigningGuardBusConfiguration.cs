using MassTransit;
using OfficeSelfSigningPortal.SigningService.Signing;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// MassTransit-Verdrahtung des SigningService — dieselbe Registrierung läuft in Produktion
/// (Program.cs) und im Transport-Slice der Integrationstests. Zwei Consumer teilen sich den
/// Sign-Endpoint: <see cref="SignMacroRequestGuardConsumer"/> (Vordertor, AK-39) und
/// <see cref="SignMacroSigningConsumer"/> (Signier-Pipeline, Ticket 08). Beide verifizieren
/// den Saga-Status unabhängig (TM-19, Defense-in-Depth).
/// </summary>
public static class SigningGuardBusConfiguration
{
    public static void AddSigningGuard(this IBusRegistrationConfigurator configurator)
    {
        configurator.AddConsumer<SignMacroRequestGuardConsumer>();
        configurator.AddConsumer<SignMacroSigningConsumer>();
    }

    /// <summary>
    /// Sign-Endpoint (ossp.sign-macro-requested) mit Retry-Policies (REQ-22,
    /// exponentiell + Jitter). Die Queue ist nur von der Saga erreichbar (REQ-14, TM-19);
    /// nach dem Retry-Limit landet die Nachricht in der MassTransit-Fault-Queue
    /// (kein Request-Verlust, TC-34, REQ-22).
    /// </summary>
    public static void ConfigureSigningGuardEndpoint(
        IReceiveEndpointConfigurator endpoint,
        IBusRegistrationContext context,
        int retryLimit,
        TimeSpan minDelay,
        TimeSpan maxDelay)
    {
        endpoint.UseMessageRetry(r => r.Intervals(
            OsspBusConventions.JitteredExponentialIntervals(retryLimit, minDelay, maxDelay)));

        endpoint.ConfigureConsumer<SignMacroRequestGuardConsumer>(context);
        endpoint.ConfigureConsumer<SignMacroSigningConsumer>(context);
    }
}
