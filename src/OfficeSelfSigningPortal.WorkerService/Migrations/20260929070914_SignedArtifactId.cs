using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSelfSigningPortal.WorkerService.Migrations
{
    /// <inheritdoc />
    public partial class SignedArtifactId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "SignedArtifactId",
                table: "analysis_saga",
                type: "uuid",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SignedArtifactId",
                table: "analysis_saga");
        }
    }
}
