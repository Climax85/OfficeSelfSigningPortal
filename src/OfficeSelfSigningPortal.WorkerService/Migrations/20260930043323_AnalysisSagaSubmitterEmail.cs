using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OfficeSelfSigningPortal.WorkerService.Migrations
{
    /// <inheritdoc />
    public partial class AnalysisSagaSubmitterEmail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SubmitterEmail",
                table: "analysis_saga",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SubmitterEmail",
                table: "analysis_saga");
        }
    }
}
