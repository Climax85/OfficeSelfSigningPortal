namespace OfficeSelfSigningPortal.WebUI.Ingestion;

/// <summary>Konfiguration der Upload-Ingestion (REQ-10, REQ-23).</summary>
public sealed class IngestionOptions
{
    public const string SectionName = "Ingestion";

    /// <summary>Maximale Upload-Größe in Bytes (Default 25 MiB, AK-37).</summary>
    public long MaxFileSizeBytes { get; set; } = 25L * 1024 * 1024;

    /// <summary>Maximales Gesamt-Kompressionsverhältnis des OOXML-Pakets (Zip-Bomb-Schwelle).</summary>
    public double MaxCompressionRatio { get; set; } = 100.0;

    /// <summary>Maximale deklarierte Gesamt-Entpackgröße in Bytes (Zip-Bomb-Schwelle).</summary>
    public long MaxDecompressedTotalBytes { get; set; } = 256L * 1024 * 1024;

    /// <summary>Erlaubte Dateiendungen (Key, ohne Punkt) → ContentType-Vertrag (Anhang A).</summary>
    public Dictionary<string, string> AllowedExtensions { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["xlsm"] = "xlsm",
        ["docm"] = "docm",
        ["pptm"] = "pptm",
    };

    /// <summary>Anzahl erlaubter Uploads pro Fenster und Einreicher (TM-14, SF-03).</summary>
    public int UploadRateLimitPermitLimit { get; set; } = 10;

    /// <summary>Fensterlänge des Upload-Rate-Limits in Sekunden (TM-14, SF-03).</summary>
    public int UploadRateLimitWindowSeconds { get; set; } = 60;
}
