using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Ossp.Audit.Migrations
{
    /// <inheritdoc />
    public partial class InitialAuditTrail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_trail",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    OccurredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Category = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Ereignis = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Aktor = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Detail = table.Column<string>(type: "text", nullable: true),
                    PrevHash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false),
                    EntryHash = table.Column<string>(type: "character(64)", fixedLength: true, maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_trail", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audit_trail_EntryHash",
                table: "audit_trail",
                column: "EntryHash");

            migrationBuilder.CreateIndex(
                name: "IX_audit_trail_JobId",
                table: "audit_trail",
                column: "JobId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_trail");
        }
    }
}
