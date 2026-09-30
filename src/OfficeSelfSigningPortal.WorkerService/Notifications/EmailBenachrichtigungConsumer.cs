using MassTransit;
using Microsoft.Extensions.Options;
using OfficeSelfSigningPortal.WorkerService.Saga;

namespace OfficeSelfSigningPortal.WorkerService.Notifications;

/// <summary>
/// Versendet die E-Mail-Benachrichtigung zum Saga-Ereignis (Ticket 10, REQ-08):
/// einreicherseitig an die persistierte Adresse (sofern der IdP einen Claim lieferte)
/// und — beim Malicious-Pfad — zusätzlich an das konfigurierte Security-Team (REQ-13).
/// Inhalt ist ausschließlich Status + Portal-Link (TM-02/TM-11) — die Nachricht führt
/// weder Dateinamen, Befunde noch andere Vorgangsdaten.
/// </summary>
public sealed class EmailBenachrichtigungConsumer(
    IEmailSender sender,
    IOptions<NotificationOptions> options) : IConsumer<BenachrichtigungAusgeloest>
{
    public async Task Consume(ConsumeContext<BenachrichtigungAusgeloest> context)
    {
        var message = context.Message;
        var link = $"{options.Value.PortalBaseUrl}/vorgang/{message.JobId}";
        var subject = $"OSSP-Vorgang: Status {message.Zustand}";
        var body = $"""
            Der Vorgang {message.JobId} hat den Status "{message.Zustand}" erreicht.

            Details und Downloads im Portal:
            {link}

            Aus Sicherheitsgründen enthält diese E-Mail ausschließlich Status und Link —
            keine Dateiinhalte, Anhänge oder Befunddetails.
            """;

        if (message.SubmitterEmail is not null)
        {
            await sender.SendAsync(message.SubmitterEmail, subject, body, context.CancellationToken);
        }

        if (message.SecurityTeam && options.Value.SecurityTeamAddress is not null)
        {
            await sender.SendAsync(
                options.Value.SecurityTeamAddress,
                $"Security-Team: {subject}",
                body,
                context.CancellationToken);
        }
    }
}
