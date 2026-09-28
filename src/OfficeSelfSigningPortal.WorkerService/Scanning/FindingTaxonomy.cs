namespace OfficeSelfSigningPortal.WorkerService.Scanning;

/// <summary>
/// Verbindliche Kategorie-Strings der <see cref="Ossp.Contracts.ScanFinding"/>-
/// Kategorien (Anhang A). Zentrale Konstanten, damit Engines und Scoring identisch arbeiten.
/// </summary>
public static class FindingCategories
{
    public const string Structure = "structure";
    public const string AutoExec = "autoexec";
    public const string SuspiciousKeyword = "suspicious-keyword";
    public const string Obfuscation = "obfuscation";
    public const string Ioc = "ioc";
    public const string YaraRule = "yara-rule";
    public const string Av = "av";
}

/// <summary>
/// Verbindliche Source-Strings der <see cref="Ossp.Contracts.ScanFinding"/>-Quellen (Anhang A).
/// </summary>
public static class FindingSources
{
    public const string Heuristic = "heuristic";
    public const string Yara = "yara";
    public const string ClamAv = "clamav";
    public const string Amsi = "amsi";
}
