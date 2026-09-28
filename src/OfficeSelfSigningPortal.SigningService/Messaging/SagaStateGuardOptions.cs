namespace OfficeSelfSigningPortal.SigningService.Messaging;

/// <summary>
/// Konfiguration des Saga-Status-Guards (TM-19): read-only Verbindung zum
/// Saga-State-Store (PostgreSQL, IF-08). In Aspire als Referenz auf die
/// Worker-Datenbank unter dem Namen <see cref="ConnectionStringName"/> injiziert.
/// </summary>
public sealed class SagaStateGuardOptions
{
    public const string SectionName = "SagaStateGuard";

    public const string ConnectionStringName = "sagastate";
}
