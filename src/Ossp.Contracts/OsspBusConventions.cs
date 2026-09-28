namespace Ossp.Contracts;

/// <summary>
/// Betriebskonventionen des Message-Bus, die mehrere Services teilen
/// (kein Nachrichtenvertrag): Retry-Intervalle mit Jitter.
/// </summary>
public static class OsspBusConventions
{
    /// <summary>
    /// Exponentielle Backoff-Intervalle mit ±25-%-Jitter.
    /// MassTransit-<c>Intervals</c>-Policies sind pro Prozessinstanz fest — der Jitter
    /// dekoriert daher je Prozessstart; gleichzeitig ausgelieferte Instanzen (Replicas,
    /// mehrere Worker) erhalten unterschiedliche Intervalle (REQ-22, TM-16).
    /// </summary>
    public static TimeSpan[] JitteredExponentialIntervals(int retryLimit, TimeSpan minDelay, TimeSpan maxDelay)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(retryLimit);

        var intervals = new TimeSpan[retryLimit];
        var current = minDelay > maxDelay ? maxDelay : minDelay;
        for (var i = 0; i < retryLimit; i++)
        {
            var jitterWindow = (int)(current.TotalMilliseconds * 0.25);
            var jittered = jitterWindow > 0
                ? current + TimeSpan.FromMilliseconds(Random.Shared.Next(-jitterWindow, jitterWindow + 1))
                : current;
            if (jittered < TimeSpan.Zero)
            {
                jittered = TimeSpan.Zero;
            }
            else if (jittered > maxDelay)
            {
                jittered = maxDelay;
            }

            intervals[i] = jittered;
            current = TimeSpan.FromTicks(Math.Min(current.Ticks * 2, maxDelay.Ticks));
        }

        return intervals;
    }
}
