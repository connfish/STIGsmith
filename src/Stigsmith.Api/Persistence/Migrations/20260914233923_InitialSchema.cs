using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Stigsmith.Api.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "checklists",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Title = table.Column<string>(type: "text", nullable: false),
                    SourceFormat = table.Column<string>(type: "text", nullable: false),
                    ImportedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    FileName = table.Column<string>(type: "text", nullable: false),
                    HostName = table.Column<string>(type: "text", nullable: false),
                    HostIp = table.Column<string>(type: "text", nullable: false),
                    HostMac = table.Column<string>(type: "text", nullable: false),
                    HostFqdn = table.Column<string>(type: "text", nullable: false),
                    TargetComment = table.Column<string>(type: "text", nullable: false),
                    Role = table.Column<string>(type: "text", nullable: false),
                    AssetType = table.Column<string>(type: "text", nullable: false),
                    TechArea = table.Column<string>(type: "text", nullable: false),
                    TargetKey = table.Column<string>(type: "text", nullable: false),
                    IsWebOrDatabase = table.Column<bool>(type: "boolean", nullable: false),
                    WebDbSite = table.Column<string>(type: "text", nullable: false),
                    WebDbInstance = table.Column<string>(type: "text", nullable: false),
                    StigId = table.Column<string>(type: "text", nullable: false),
                    StigTitle = table.Column<string>(type: "text", nullable: false),
                    StigVersion = table.Column<string>(type: "text", nullable: false),
                    StigReleaseInfo = table.Column<string>(type: "text", nullable: false),
                    OriginalDocument = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_checklists", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "findings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ChecklistId = table.Column<Guid>(type: "uuid", nullable: false),
                    RuleId = table.Column<string>(type: "text", nullable: false),
                    GroupId = table.Column<string>(type: "text", nullable: false),
                    NumericId = table.Column<string>(type: "text", nullable: false),
                    RuleVersion = table.Column<string>(type: "text", nullable: false),
                    Title = table.Column<string>(type: "text", nullable: false),
                    Severity = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<string>(type: "text", nullable: false),
                    FindingDetails = table.Column<string>(type: "text", nullable: false),
                    Comments = table.Column<string>(type: "text", nullable: false),
                    FixText = table.Column<string>(type: "text", nullable: false),
                    CheckContent = table.Column<string>(type: "text", nullable: false),
                    Discussion = table.Column<string>(type: "text", nullable: false),
                    CciRefs = table.Column<string>(type: "text", nullable: false),
                    Automatability = table.Column<string>(type: "text", nullable: false),
                    ClassificationReason = table.Column<string>(type: "text", nullable: false),
                    IsHighRisk = table.Column<bool>(type: "boolean", nullable: false),
                    RiskCategories = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_findings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_findings_checklists_ChecklistId",
                        column: x => x.ChecklistId,
                        principalTable: "checklists",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "generations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    Provider = table.Column<string>(type: "text", nullable: false),
                    Model = table.Column<string>(type: "text", nullable: false),
                    ParametersJson = table.Column<string>(type: "jsonb", nullable: false),
                    SystemPrompt = table.Column<string>(type: "text", nullable: false),
                    UserPrompt = table.Column<string>(type: "text", nullable: false),
                    PromptSha256 = table.Column<string>(type: "text", nullable: false),
                    RawResponse = table.Column<string>(type: "text", nullable: false),
                    Yaml = table.Column<string>(type: "text", nullable: false),
                    RetrievedExampleIds = table.Column<string>(type: "text", nullable: false),
                    TargetOs = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PromptTokens = table.Column<int>(type: "integer", nullable: false),
                    CompletionTokens = table.Column<int>(type: "integer", nullable: false),
                    Error = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_generations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_generations_findings_FindingId",
                        column: x => x.FindingId,
                        principalTable: "findings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "validation_runs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GenerationId = table.Column<Guid>(type: "uuid", nullable: false),
                    Outcome = table.Column<string>(type: "text", nullable: false),
                    FailedStage = table.Column<string>(type: "text", nullable: false),
                    RepairAttempt = table.Column<int>(type: "integer", nullable: false),
                    LintOutput = table.Column<string>(type: "text", nullable: false),
                    SyntaxCheckOutput = table.Column<string>(type: "text", nullable: false),
                    ApplyOutput = table.Column<string>(type: "text", nullable: false),
                    ScanStatusBefore = table.Column<string>(type: "text", nullable: false),
                    ScanStatusAfter = table.Column<string>(type: "text", nullable: false),
                    IdempotencyOutput = table.Column<string>(type: "text", nullable: false),
                    IdempotencyChangedCount = table.Column<int>(type: "integer", nullable: false),
                    ContainerImage = table.Column<string>(type: "text", nullable: false),
                    EvidenceJson = table.Column<string>(type: "jsonb", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_validation_runs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_validation_runs_generations_GenerationId",
                        column: x => x.GenerationId,
                        principalTable: "generations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_checklists_HostName",
                table: "checklists",
                column: "HostName");

            migrationBuilder.CreateIndex(
                name: "IX_checklists_ImportedAt",
                table: "checklists",
                column: "ImportedAt");

            migrationBuilder.CreateIndex(
                name: "IX_findings_ChecklistId_Automatability",
                table: "findings",
                columns: new[] { "ChecklistId", "Automatability" });

            migrationBuilder.CreateIndex(
                name: "IX_findings_ChecklistId_RuleId",
                table: "findings",
                columns: new[] { "ChecklistId", "RuleId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_findings_ChecklistId_Status",
                table: "findings",
                columns: new[] { "ChecklistId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_findings_NumericId",
                table: "findings",
                column: "NumericId");

            migrationBuilder.CreateIndex(
                name: "IX_generations_FindingId_CreatedAt",
                table: "generations",
                columns: new[] { "FindingId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_validation_runs_GenerationId_StartedAt",
                table: "validation_runs",
                columns: new[] { "GenerationId", "StartedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "validation_runs");

            migrationBuilder.DropTable(
                name: "generations");

            migrationBuilder.DropTable(
                name: "findings");

            migrationBuilder.DropTable(
                name: "checklists");
        }
    }
}
