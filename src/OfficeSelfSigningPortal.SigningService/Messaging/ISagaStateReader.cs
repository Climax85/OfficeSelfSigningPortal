namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// Liest den persistierten Saga-Status eines Vorgangs (Defense-in-Depth für den
/// SigningService, TM-19/AK-39/TC-30): Die Sign-Queue ist nur von der Saga
/// erreichbar; trotzdem verifiziert der Consumer den Vorgangsstatus unabhängig
/// von der Nachricht selbst, bevor eine Signatur erzeugt wird.
/// </summary>
public interface ISagaStateReader
{
    /// <summary>Liefert den Zustandsnamen (Anhang B) oder null, wenn keine Saga existiert.</summary>
    Task<string?> GetSagaStateAsync(Guid jobId, CancellationToken cancellationToken);
}
