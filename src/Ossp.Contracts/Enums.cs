namespace Ossp.Contracts;

/// <summary>
/// Verdichte der Analyse (Anhang D). <see cref="Inconclusive"/> wird ausschließlich
/// vom optionalen AMSI-Stage bei dessen Ausfall/Timeout erzeugt (nie von der Baseline).
/// </summary>
public enum Verdict
{
    Clean,
    Suspicious,
    Malicious,
    Inconclusive,
    Error,
}

/// <summary>
/// Zustand einer Engine-Stage. <see cref="Absent"/> = Stage nicht deployt
/// (z. B. AMSI-Bridge im Profil <c>baseline</c>).
/// </summary>
public enum EngineState
{
    Ok,
    Degraded,
    Failed,
    Absent,
}
