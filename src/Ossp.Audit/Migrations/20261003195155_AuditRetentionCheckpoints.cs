using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Ossp.Audit.Migrations
{
    /// <inheritdoc />
    public partial class AuditRetentionCheckpoints : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_chain_checkpoints",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    SetAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastDeletedEntryHash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                    FirstRemainingEntryId = table.Column<long>(type: "bigint", nullable: false),
                    DeletedCount = table.Column<long>(type: "bigint", nullable: false),
                    Aktor = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Reason = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_chain_checkpoints", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audit_chain_checkpoints_LastDeletedEntryHash",
                table: "audit_chain_checkpoints",
                column: "LastDeletedEntryHash");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_chain_checkpoints");
        }
    }
}
