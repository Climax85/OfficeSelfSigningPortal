using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace OfficeSelfSigningPortal.WorkerService.Migrations
{
    /// <inheritdoc />
    public partial class DropSagaAuditEntries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "saga_audit_entries");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "saga_audit_entries",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Aktor = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Detail = table.Column<string>(type: "text", nullable: true),
                    Ereignis = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Zustand = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_saga_audit_entries", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_saga_audit_entries_JobId",
                table: "saga_audit_entries",
                column: "JobId");
        }
    }
}
