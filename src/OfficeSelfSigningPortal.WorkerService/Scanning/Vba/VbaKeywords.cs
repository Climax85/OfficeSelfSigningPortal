using System.Text.RegularExpressions;

namespace OfficeSelfSigningPortal.WorkerService.Scanning.Vba;

/// <summary>
/// VBA-Keyword-Vokabular des Heuristik-Scorers (Anhang D, aus olevba/mraptor
/// abgeleitet): AutoExec-Trigger (mraptor-Klasse A), Verhaltens-Gruppen
/// (mraptor-Klassen W/X) und Obfuscation-Indikatoren. Keywords sind im Klartext
/// nicht obfuszierbar — die dokumentierte Grundlage der mraptor-Logik.
/// </summary>
public static partial class VbaKeywords
{
    /// <summary>AutoExec-Trigger — mraptor-Klasse A (je Treffer ein Finding).</summary>
    public static readonly (string Keyword, Regex Pattern)[] AutoExec =
    [
        ("AutoExec", AutoExecPattern("AutoExec")),
        ("AutoOpen", AutoExecPattern("AutoOpen")),
        ("Auto_Open", AutoExecPattern("Auto_Open")),
        ("AutoClose", AutoExecPattern("AutoClose")),
        ("Auto_Close", AutoExecPattern("Auto_Close")),
        ("Workbook_Open", AutoExecPattern("Workbook_Open")),
        ("Workbook_Activate", AutoExecPattern("Workbook_Activate")),
        ("Document_Open", AutoExecPattern("Document_Open")),
        ("Document_Close", AutoExecPattern("Document_Close")),
    ];

    /// <summary>
    /// Verhaltens-Gruppen (Anhang D: je Gruppe +10, Cap +30). Klassifizierung nach
    /// mraptor: X = ausführen, W = Datei schreiben/Dropper.
    /// </summary>
    public static readonly (string Group, bool IsWriteClass, bool IsExecuteClass, Regex[] Patterns)[] BehaviorGroups =
    [
        ("shell-exec", IsWriteClass: false, IsExecuteClass: true,
            [PlainKeywordPattern("Shell"), PlainKeywordPattern("WinExec"), EscapedPattern("WScript\\.Shell")]),
        ("object-creation", IsWriteClass: false, IsExecuteClass: true,
            [PlainKeywordPattern("CreateObject"), PlainKeywordPattern("GetObject")]),
        ("filesystem", IsWriteClass: true, IsExecuteClass: false,
            [EscapedPattern("FileSystemObject"), PlainKeywordPattern("CreateTextFile"), PlainKeywordPattern("SaveToFile"), PlainKeywordPattern("CopyFile")]),
        ("download", IsWriteClass: true, IsExecuteClass: false,
            [EscapedPattern("URLDownloadToFile(?:Ex)?"), PlainKeywordPattern("WinHttpRequest"), EscapedPattern("XMLHTTP"), PlainKeywordPattern("DownloadString")]),
    ];

    /// <summary>Schwelle der Chr()-Dichte als Obfuscation-Indikator (Anhang D).</summary>
    public const int ChrDensityThreshold = 8;

    private static Regex AutoExecPattern(string keyword) =>
        new($@"\b{Regex.Escape(keyword)}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    private static Regex PlainKeywordPattern(string keyword) =>
        new($@"\b{keyword}\b", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    private static Regex EscapedPattern(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    public static partial class Ioc
    {
        public static readonly Regex Url = UrlPattern();
        public static readonly Regex IPv4 = Ipv4Pattern();
        public static readonly Regex ExeName = ExeNamePattern();

        [GeneratedRegex("""https?://[^\s"')]+""", RegexOptions.IgnoreCase)]
        private static partial Regex UrlPattern();

        [GeneratedRegex("""\b\d{1,3}(?:\.\d{1,3}){3}\b""")]
        private static partial Regex Ipv4Pattern();

        [GeneratedRegex("""\b[A-Za-z0-9_-]{1,64}\.exe\b""", RegexOptions.IgnoreCase)]
        private static partial Regex ExeNamePattern();
    }

    [GeneratedRegex("""&H[0-9A-Fa-f]{1,6}\b""")]
    public static partial Regex HexString();

    [GeneratedRegex("""[A-Za-z0-9+/]{32,}={0,2}""")]
    public static partial Regex Base64Literal();

    [GeneratedRegex("""\bStrReverse\s*\(""")]
    public static partial Regex StrReverseCall();

    [GeneratedRegex("""\bChr(?:\$|B)?\s*\(""", RegexOptions.IgnoreCase)]
    public static partial Regex ChrCall();
}
