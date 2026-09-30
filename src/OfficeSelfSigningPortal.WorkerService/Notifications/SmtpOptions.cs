namespace OfficeSelfSigningPortal.WorkerService.Notifications;

/// <summary>
/// SMTP-Konfiguration des WorkerService (Ticket 10, REQ-21). Ohne
/// <see cref="Host"/> ist der E-Mail-Pfad deaktiviert — das Portal läuft vollständig
/// ohne E-Mail-Fehler oder Blockaden weiter (AK-21, TC-42). Secrets (Password)
/// ausschließlich per Umgebungsvariable/User-Secrets (TM-12), niemals im Repository.
/// </summary>
public sealed class SmtpOptions
{
    public const string SectionName = "Smtp";

    /// <summary>SMTP-Server; null/leer = E-Mail-Pfad deaktiviert.</summary>
    public string? Host { get; set; }

    /// <summary>SMTP-Port (587 = STARTTLS, 465 = implizites TLS).</summary>
    public int Port { get; set; } = 587;

    public string? UserName { get; set; }

    public string? Password { get; set; }

    /// <summary>Absenderadresse; Pflicht, sobald <see cref="Host"/> konfiguriert ist.</summary>
    public string? From { get; set; }

    /// <summary>
    /// Ausschließlich für den lokalen MailPit-Dev-Container (selbstsigniertes
    /// Zertifikat): deaktiviert die Zertifikatsprüfung. Im Betrieb niemals setzen
    /// (TM-11: TLS-Zwang inklusive Prüfung).
    /// </summary>
    public bool DisableCertificateValidation { get; set; }
}
