using System.Collections.Concurrent;

namespace OfficeSelfSigningPortal.WebUI.LiveStatus;

/// <summary>
/// Single-Replica-Registratur der aktiven Hub-Beobachtungen (REQ-20): Der
/// Status-Wächter (<see cref="StatusChangeNotifier"/>) fragt ausschließlich
/// beobachtete Vorgänge ab und merkt sich den zuletzt bekannten Zustand, um
/// nur bei tatsächlicher Änderung zu pushen. Referenzzählung pro Verbindung —
/// Gruppenmitgliedschaften verwaltet der Hub, diese Tracker nur die Abfrage-Seite.
/// </summary>
public sealed class StatusWatchTracker
{
    private readonly ConcurrentDictionary<string, ConnectionWatches> _connections = new();

    public IReadOnlyList<Guid> WatchedJobs
        => _connections.Values.SelectMany(w => w.Jobs).Distinct().ToList();

    public bool DashboardWatched => _connections.Values.Any(w => w.Dashboard);

    /// <summary>Zuletzt an Beobachter gepushter Zustand pro Vorgang (Vergleichsbasis).</summary>
    private readonly ConcurrentDictionary<Guid, JobSnapshot> _lastKnown = new();

    public void AddJobWatch(string connectionId, Guid jobId)
    {
        var watches = _connections.GetOrAdd(connectionId, _ => new ConnectionWatches());
        lock (watches)
        {
            watches.Jobs.Add(jobId);
        }
    }

    public void MarkDashboardWatched(string connectionId)
        => _connections.GetOrAdd(connectionId, _ => new ConnectionWatches()).Dashboard = true;

    /// <summary>
    /// Verbindung getrennt — liefert true, wenn keine Beobachtungen mehr bestehen
    /// (letzte Freigabe; der Aufrufer kann den Zustandscache des Vorgangs verwerfen).
    /// </summary>
    public bool RemoveConnection(string connectionId)
    {
        _connections.TryRemove(connectionId, out _);
        return _connections.IsEmpty;
    }

    /// <summary>
    /// Aktualisiert den bekannten Zustand; liefert true bei Änderung gegenüber
    /// der vorherigen Push-Basis (oder beim ersten Bekanntwerden).
    /// </summary>
    public bool TryUpdateLastKnown(Guid jobId, string state, Guid? signedArtifactId)
    {
        var snapshot = new JobSnapshot(state, signedArtifactId);
        if (!_lastKnown.TryGetValue(jobId, out var previous))
        {
            _lastKnown[jobId] = snapshot;
            return true;
        }

        if (previous.State == state && previous.SignedArtifactId == signedArtifactId)
        {
            return false;
        }

        _lastKnown[jobId] = snapshot;
        return true;
    }

    /// <summary>Zuletzt an das Dashboard gepushter Fingerabdruck (offene Reviews).</summary>
    private string _dashboardFingerprint = string.Empty;

    /// <summary>
    /// Fingerabdruck einer offenen-Reviews-Liste — gemeinsames Format von Hub
    /// (Watch-Baseline) und Wächter (Änderungserkennung), damit keine Pseudo-
    /// Änderung durch Formatdrift entsteht.
    /// </summary>
    public static string FingerprintOf(IEnumerable<Review.SagaVorgangInfo> open)
        => string.Join('|', open.Select(v => $"{v.JobId}:{v.CurrentState}:{v.ReceivedAt:O}"));

    /// <summary>
    /// Vergleicht den Fingerabdruck der offenen Reviews mit der letzten Push-Basis;
    /// liefert true bei Änderung (oder beim ersten Aufruf).
    /// </summary>
    public bool TryUpdateDashboardFingerprint(string fingerprint)
    {
        if (string.Equals(_dashboardFingerprint, fingerprint, StringComparison.Ordinal))
        {
            return false;
        }

        _dashboardFingerprint = fingerprint;
        return true;
    }

    /// <summary>Verwirft die Push-Basis aller Vorgänge (letzte Verbindung getrennt).</summary>
    public void ForgetLastKnown() => _lastKnown.Clear();

    private sealed record JobSnapshot(string State, Guid? SignedArtifactId);

    private sealed class ConnectionWatches
    {
        public HashSet<Guid> Jobs { get; } = [];
        public bool Dashboard { get; set; }
    }
}
