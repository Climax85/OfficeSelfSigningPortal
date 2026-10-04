using Ossp.AmsiScanBridge;

namespace OfficeSelfSigningPortal.Tests.AmsiScanBridge;

/// <summary>
/// Test-Doppel für <see cref="IAmsiScanner"/>: liefert ein festes Ergebnis
/// (Clean oder Detected) und führt den realen Windows-AMSI-Aufruf nicht aus.
/// Plattformneutral; Tests laufen auf Linux/Windows/macOS identisch.
/// </summary>
internal sealed class FakeAmsiScanner : IAmsiScanner
{
    private readonly AmsiDetection _detection;

    public FakeAmsiScanner(AmsiDetection detection)
    {
        _detection = detection;
    }

    public Task<AmsiDetection> ScanAsync(AmsiScanCall call, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_detection);
    }
}

/// <summary>
/// Aufzeichnender Test-Doppel für <see cref="IAmsiScanner"/>: vermerkt jeden
/// Aufruf samt Content-Namen für Inhalts-Verifikation.
/// </summary>
internal sealed class RecordingAmsiScanner : IAmsiScanner
{
    private readonly AmsiDetection _detection;

    public RecordingAmsiScanner(AmsiDetection detection)
    {
        _detection = detection;
    }

    public List<AmsiScanCall> LastCalls { get; } = new();

    public Task<AmsiDetection> ScanAsync(AmsiScanCall call, CancellationToken cancellationToken)
    {
        LastCalls.Add(call);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_detection);
    }
}