using System.Net;
using System.Text.RegularExpressions;

namespace OfficeSelfSigningPortal.WebUI.Review;

/// <summary>
/// Filter für den Rückfrage-Kanal (AK-49, TC-26, TM-02): Link-/Markup-Inhalte
/// werden vor der Publikation escapet — kein aktiver Inhalt erreicht Bus, Audit-
/// Trail oder Portal-Anzeige. Vollständiges Escaping aller Markup-Metazeichen
/// statt Tag-Whitelisting (der Kanal ist Plaintext, Umlaute bleiben lesbar);
/// zusätzlich werden gefährliche URI-Schemes (javascript:/vbscript:/data:)
/// entwertet, damit weder HTML- noch Markdown-Renderings aktive Links erzeugen.
/// </summary>
public static partial class RueckfrageTextSanitizer
{
    public static string Sanitize(string input)
    {
        var escaped = WebUtility.HtmlEncode(input);
        return DangerousScheme().Replace(escaped, "$1&#58;");
    }

    [GeneratedRegex("(?i)(javascript|vbscript|data)\\s*:", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DangerousScheme();
}
