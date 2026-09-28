using MassTransit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// MassTransit-Verdrahtung des SigningService (Guard-Consumer) — dieselbe
/// Registrierung läuft in Produktion (Program.cs) und im Transport-Slice der
/// Integrationstests.
/// </summary>
public static class SigningGuardBusConfiguration
{
    public static void AddSigningGuard(this IBusRegistrationConfigurator configurator)
        => configurator.AddConsumer<SignMacroRequestGuardConsumer>();

    /// <summary>
    /// Sign-Endpoint (ossp.sign-macro-requested) mit Retry-Policies (REQ-22,
    /// exponentiell + Jitter).
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
    }
}
