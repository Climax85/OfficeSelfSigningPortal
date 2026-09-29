using System.Text.Json;
using MassTransit;
using Ossp.Contracts;

namespace OfficeSelfSigningPortal.WorkerService.Saga;

/// <summary>
/// Persistierte Evidenz des Auto-Signings im Audit-Trail (TM-08, REQ-13, AK-13):
/// Score, ScoreVersion, Findings und EngineStates des auslösenden Clean-Scans —
/// zusammen mit <see cref="SignMacroRequested.RequestedBy">system:auto-sign</see>
/// bleibt der Vorgang vollständig rekonstruierbar.
/// </summary>
public sealed record AutoSignEvidence(
    int Score,
    string ScoreVersion,
    IReadOnlyList<ScanFinding> Findings,
    IReadOnlyList<EngineResult> Engines);

/// <summary>
/// AnalysisSaga — persistierte State Machine des Analyseauftrags (Anhang B, verbindlich:
/// genau die dort definierten Übergänge und Endzustände; REQ-11, REQ-25, AK-38).
///
/// Auslagerung vor den Bus (Ingestion, Ticket 03): Format-/Größen-/Passwort-Validierung,
/// Zip-Bomb/Polyglot-Prüfung und Makrofrei-Filter laufen vor der Persistierung — die
/// Anhang-B-Verzweigungen aus <c>InValidierung</c> bleiben für den Fehlerpfad verdrahtet
/// (<see cref="JobFailed"/> Stage "ingestion") bzw. als internes Ereignis
/// (<see cref="MakrofreieDateiErkannt"/>), erreichen in v1 aber den Bus nicht.
///
/// Übergänge werden je als Audit-Eintrag geschrieben (Anhang B, REQ-18); Nachrichten der
/// Saga laufen über die EF-Core-Outbox (REQ-11, TM-06). Endzustände verbleiben als
/// persistierte Zeile (kein Abschluss-Löschen) — die Saga-Zeile ist der Vorgangsstatus.
/// </summary>
public sealed class AnalysisSaga : MassTransitStateMachine<AnalysisSagaState>
{
    private readonly ISagaAuditWriter _audit;

    // Zustände (Anhang B). "Eingereicht" ist die Aufnahmephase vor InValidierung und
    // wird als Audit-Eintrag beim Saga-Start protokolliert.
    public State InValidierung { get; private set; } = null!;
    public State ScanLaeuft { get; private set; } = null!;
    public State ReviewAusstehend { get; private set; } = null!;
    public State RueckfrageAusstehend { get; private set; } = null!;
    public State SignierungAngefragt { get; private set; } = null!;
    public State Signiert { get; private set; } = null!;
    public State Abgelehnt { get; private set; } = null!;
    public State NichtSignierbar { get; private set; } = null!;
    public State Fehler { get; private set; } = null!;

    public Event<ScanRequested> ScanAuftragEingegangen { get; private set; } = null!;
    public Event<ValidierungAbgeschlossen> ValidierungBeendet { get; private set; } = null!;
    public Event<MakrofreieDateiErkannt> MakrofreiErkannt { get; private set; } = null!;
    public Event<ScanCompleted> ScanErgebnisEingegangen { get; private set; } = null!;
    public Event<ReviewDecisionRecorded> ReviewEntscheidungEingegangen { get; private set; } = null!;
    public Event<EinreicherAntwortEingegangen> EinreicherAntwortEingegangen { get; private set; } = null!;
    public Event<SignMacroCompleted> SignaturErfolgreich { get; private set; } = null!;
    public Event<SignMacroFailed> SignaturFehlgeschlagen { get; private set; } = null!;
    public Event<JobFailed> AufgabeFehlgeschlagen { get; private set; } = null!;

    public AnalysisSaga(ISagaAuditWriter audit)
    {
        _audit = audit;

        InstanceState(x => x.CurrentState);

        State(() => InValidierung);
        State(() => ScanLaeuft);
        State(() => ReviewAusstehend);
        State(() => RueckfrageAusstehend);
        State(() => SignierungAngefragt);
        State(() => Signiert);
        State(() => Abgelehnt);
        State(() => NichtSignierbar);
        State(() => Fehler);

        Event(() => ScanAuftragEingegangen, e => e.CorrelateById(ctx => ctx.Message.JobId));
        // Späte/duplizierte Ereignisse für unbekannte Vorgänge werden verworfen
        // (kein SagaNotFound-Fehlschlag in die Error-Queue).
        Event(() => ValidierungBeendet, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => MakrofreiErkannt, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => ScanErgebnisEingegangen, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => ReviewEntscheidungEingegangen, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => EinreicherAntwortEingegangen, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => SignaturErfolgreich, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => SignaturFehlgeschlagen, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });
        Event(() => AufgabeFehlgeschlagen, e =>
        {
            e.CorrelateById(ctx => ctx.Message.JobId);
            e.OnMissingInstance(m => m.Discard());
        });

        Initially(
            When(ScanAuftragEingegangen)
                .ThenAsync(async ctx =>
                {
                    var msg = ctx.Message;
                    ctx.Saga.ArtifactId = msg.ArtifactId;
                    ctx.Saga.ContentSha256 = msg.ContentSha256;
                    ctx.Saga.OriginalFileName = msg.OriginalFileName;
                    ctx.Saga.ContentType = msg.ContentType;
                    ctx.Saga.FileSizeBytes = msg.FileSizeBytes;
                    ctx.Saga.SubmittedBy = msg.SubmittedBy;
                    ctx.Saga.ReceivedAt = msg.RequestedAt;
                    await AuditAsync(ctx, SagaStateNames.Eingereicht, "Upload persistiert", msg.SubmittedBy, msg.OriginalFileName);
                })
                .Publish(ctx => new ValidierungAbgeschlossen(ctx.Saga.CorrelationId))
                .TransitionTo(InValidierung));

        During(InValidierung,
            When(ValidierungBeendet)
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.ScanLaeuft, "Validierung abgeschlossen — Scan startet", "system:saga", null))
                .TransitionTo(ScanLaeuft),
            When(MakrofreiErkannt)
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.NichtSignierbar, "Datei makrofrei — nicht signierbar", "system:saga", null))
                .TransitionTo(NichtSignierbar),
            When(AufgabeFehlgeschlagen, ctx => ctx.Message.Stage == "ingestion")
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.Abgelehnt, "Upload-Regel verletzt", "system:saga", ctx.Message.Reason))
                .TransitionTo(Abgelehnt));

        During(ScanLaeuft,
            When(ScanErgebnisEingegangen, ctx => ctx.Message.Verdict == Verdict.Clean)
                .ThenAsync(async ctx =>
                {
                    await ctx.Publish(new SignMacroRequested(
                        ctx.Saga.CorrelationId,
                        ctx.Saga.ArtifactId,
                        ctx.Saga.ContentSha256,
                        ctx.Saga.OriginalFileName,
                        ctx.Saga.ContentType,
                        RequestedBy: "system:auto-sign",
                        DateTimeOffset.UtcNow));
                    await AuditAsync(
                        ctx,
                        SagaStateNames.SignierungAngefragt,
                        $"Scan Clean (Score {ctx.Message.Score}, {ctx.Message.ScoreVersion}) — Auto-Signierung angefragt",
                        "system:auto-sign",
                        // Vollständige Auto-Signing-Evidenz (TM-08, REQ-13): Findings, Score,
                        // ScoreVersion und EngineStates machen den Vorgang rekonstruierbar.
                        JsonSerializer.Serialize(new AutoSignEvidence(
                            ctx.Message.Score,
                            ctx.Message.ScoreVersion,
                            ctx.Message.Findings,
                            ctx.Message.Engines)));
                })
                .TransitionTo(SignierungAngefragt),
            When(ScanErgebnisEingegangen, ctx => ctx.Message.Verdict is Verdict.Suspicious or Verdict.Inconclusive)
                .ThenAsync(async ctx =>
                    await AuditAsync(
                        ctx,
                        SagaStateNames.ReviewAusstehend,
                        ctx.Message.Verdict == Verdict.Inconclusive
                            ? "Scan Inconclusive (AMSI-Ausfall) — Review-Pflicht"
                            : $"Scan Suspicious (Score {ctx.Message.Score}, {ctx.Message.ScoreVersion}) — Review-Pflicht",
                        "system:saga",
                        null))
                .TransitionTo(ReviewAusstehend),
            When(ScanErgebnisEingegangen, ctx => ctx.Message.Verdict == Verdict.Malicious)
                .ThenAsync(async ctx =>
                    await AuditAsync(
                        ctx,
                        SagaStateNames.Abgelehnt,
                        $"Scan Malicious (Score {ctx.Message.Score}, {ctx.Message.ScoreVersion}) — abgelehnt",
                        "system:saga",
                        // Security-Team-Benachrichtigung verdrahtet Ticket 10 (E-Mail-Pfad).
                        "Security-Benachrichtigung folgt (Ticket 10)"))
                .TransitionTo(Abgelehnt),
            When(ScanErgebnisEingegangen, ctx => ctx.Message.Verdict == Verdict.Error)
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.Fehler, "Scan-Fehler", "system:saga", ctx.Message.ScoreVersion))
                .TransitionTo(Fehler),
            When(AufgabeFehlgeschlagen, ctx => ctx.Message.Stage == "scan")
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.Fehler, "Scan nach Retry-Limit fehlgeschlagen", "system:saga", ctx.Message.Reason))
                .TransitionTo(Fehler));

        During(ReviewAusstehend,
            // SoD (REQ-17, TM-18, TC-22): Freigabe durch denselben Account wird abgelehnt;
            // der Vorgang bleibt ReviewAusstehend und ist einem zweiten Bearbeiter vorbehalten.
            // JobFailed(stage "review") ist das Meldungs-/Audit-Event — die Saga behandelt
            // es nicht selbst (kein Eintrag in Anhang B, Selbst-Loop vermeiden).
            When(ReviewEntscheidungEingegangen,
                    ctx => ctx.Message.Decision == ReviewDecisionValues.Freigeben
                        && string.Equals(ctx.Message.ReviewerId, ctx.Saga.SubmittedBy, StringComparison.Ordinal))
                .ThenAsync(async ctx =>
                {
                    await ctx.Publish(new JobFailed(
                        ctx.Saga.CorrelationId,
                        "review",
                        "SoD-Verletzung: ReviewerId == SubmitterId",
                        Retryable: false,
                        DateTimeOffset.UtcNow));
                    await AuditAsync(ctx, SagaStateNames.ReviewAusstehend, "SoD-Verletzung — Freigabe abgelehnt", ctx.Message.ReviewerId, null);
                }),
            When(ReviewEntscheidungEingegangen,
                    ctx => ctx.Message.Decision == ReviewDecisionValues.Freigeben
                        && !string.Equals(ctx.Message.ReviewerId, ctx.Saga.SubmittedBy, StringComparison.Ordinal))
                .ThenAsync(async ctx =>
                {
                    await ctx.Publish(new SignMacroRequested(
                        ctx.Saga.CorrelationId,
                        ctx.Saga.ArtifactId,
                        ctx.Saga.ContentSha256,
                        ctx.Saga.OriginalFileName,
                        ctx.Saga.ContentType,
                        RequestedBy: ctx.Message.ReviewerId,
                        DateTimeOffset.UtcNow));
                    await AuditAsync(ctx, SagaStateNames.SignierungAngefragt, "Review-Freigabe — Signierung angefragt", ctx.Message.ReviewerId, ctx.Message.Comment);
                })
                .TransitionTo(SignierungAngefragt),
            When(ReviewEntscheidungEingegangen, ctx => ctx.Message.Decision == ReviewDecisionValues.Ablehnen)
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.Abgelehnt, "Review-Ablehnung", ctx.Message.ReviewerId, ctx.Message.Comment))
                .TransitionTo(Abgelehnt),
            When(ReviewEntscheidungEingegangen, ctx => ctx.Message.Decision == ReviewDecisionValues.Rueckfrage)
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.RueckfrageAusstehend, "Review-Rückfrage gestellt", ctx.Message.ReviewerId, ctx.Message.Comment))
                .TransitionTo(RueckfrageAusstehend));

        During(RueckfrageAusstehend,
            When(EinreicherAntwortEingegangen)
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.ReviewAusstehend, "Einreicher-Antwort eingegangen", ctx.Message.SubmittedBy, ctx.Message.Antwort))
                .TransitionTo(ReviewAusstehend));

        During(SignierungAngefragt,
            When(SignaturErfolgreich)
                .ThenAsync(async ctx =>
                {
                    // Signatur-Referenz persistieren (Download TC-27/AK-04 via T09,
                    // Retention T11) und Benachrichtigung des Einreichers verdrahtet Ticket 10.
                    ctx.Saga.SignedArtifactId = ctx.Message.SignedArtifactId;
                    await AuditAsync(ctx, SagaStateNames.Signiert, "Signierung abgeschlossen", "system:signing-service", null);
                })
                .TransitionTo(Signiert),
            When(SignaturFehlgeschlagen, ctx => !ctx.Message.Retryable)
                .ThenAsync(async ctx =>
                {
                    // Alarm-Hook für den Betrieb/Notification-Pfad (Ticket 10); JobFailed ist
                    // in SignierungAngefragt der fachliche Fehlerpfad (Anhang B: Fehler + Alarm).
                    await ctx.Publish(new JobFailed(
                        ctx.Saga.CorrelationId,
                        "signing",
                        ctx.Message.Reason,
                        Retryable: false,
                        DateTimeOffset.UtcNow));
                    await AuditAsync(ctx, SagaStateNames.Fehler, "Signierung endgültig fehlgeschlagen", "system:signing-service", ctx.Message.Reason);
                })
                .TransitionTo(Fehler),
            When(SignaturFehlgeschlagen, ctx => ctx.Message.Retryable)
                .ThenAsync(async ctx =>
                    // Retryable: MassTransit-Redelivery am SigningService (exponentiell + Jitter,
                    // REQ-22) — die Saga bleibt in SignierungAngefragt (Anhang B).
                    await AuditAsync(ctx, SagaStateNames.SignierungAngefragt, "Signierung vorübergehend fehlgeschlagen — Retry", "system:signing-service", ctx.Message.Reason)),
            When(AufgabeFehlgeschlagen, ctx => ctx.Message.Stage == "signing")
                .ThenAsync(async ctx =>
                    await AuditAsync(ctx, SagaStateNames.Fehler, "Signierung nach Retry-Limit fehlgeschlagen", "system:saga", ctx.Message.Reason))
                .TransitionTo(Fehler));
    }

    private Task AuditAsync(
        BehaviorContext<AnalysisSagaState> context,
        string zustand,
        string ereignis,
        string aktor,
        string? detail)
        => _audit.WriteAsync(context.Saga.CorrelationId, zustand, ereignis, aktor, detail, CancellationToken.None);
}
