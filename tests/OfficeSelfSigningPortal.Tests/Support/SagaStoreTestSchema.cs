namespace OfficeSelfSigningPortal.Tests.Support;

/// <summary>
/// DDL-Spiegelung der <c>analysis_saga</c>-Tabelle (WorkerService-Migration) für
/// Seam-S1-Fixtures — der WebUI-Reader ist bewusst schema-parallel zum
/// SigningService, kein EF-Pfad über ein fremdes Schema. Muss bei neuen
/// Saga-Spalten (z. B. SignedArtifactId, T08) nachgezogen werden.
/// </summary>
public static class SagaStoreTestSchema
{
    public const string SagaTableDdl = """
        CREATE TABLE "analysis_saga" (
            "CorrelationId" uuid NOT NULL PRIMARY KEY,
            "CurrentState" character varying(64) NOT NULL,
            "SubmittedBy" character varying(256) NOT NULL,
            "ArtifactId" uuid NOT NULL,
            "ContentSha256" character varying(64) NOT NULL,
            "OriginalFileName" character varying(512) NOT NULL,
            "ContentType" character varying(16) NOT NULL,
            "FileSizeBytes" bigint NOT NULL,
            "ReceivedAt" timestamp with time zone NOT NULL,
            "SignedArtifactId" uuid NULL
        );
        CREATE INDEX "IX_analysis_saga_ReceivedAt" ON "analysis_saga" ("ReceivedAt");
        """;
}
