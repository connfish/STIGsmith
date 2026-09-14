using Microsoft.EntityFrameworkCore;

namespace Stigsmith.Api.Persistence;

public sealed class StigsmithDbContext(DbContextOptions<StigsmithDbContext> options) : DbContext(options)
{
    public DbSet<ChecklistRecord> Checklists => Set<ChecklistRecord>();
    public DbSet<FindingRecord> Findings => Set<FindingRecord>();
    public DbSet<GenerationRecord> Generations => Set<GenerationRecord>();
    public DbSet<ValidationRunRecord> ValidationRuns => Set<ValidationRunRecord>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<ChecklistRecord>(e =>
        {
            e.ToTable("checklists");
            e.HasIndex(x => x.ImportedAt);
            e.HasIndex(x => x.HostName);
            e.Property(x => x.SourceFormat).HasConversion<string>();
        });

        b.Entity<FindingRecord>(e =>
        {
            e.ToTable("findings");
            e.HasOne(x => x.Checklist).WithMany(x => x.Findings)
                .HasForeignKey(x => x.ChecklistId).OnDelete(DeleteBehavior.Cascade);
            // Triage filters by status and severity constantly; classification drives the generation
            // queue's work selection. Both get an index.
            e.HasIndex(x => new { x.ChecklistId, x.Status });
            e.HasIndex(x => new { x.ChecklistId, x.Automatability });
            e.HasIndex(x => x.NumericId);
            e.HasIndex(x => new { x.ChecklistId, x.RuleId }).IsUnique();
            e.Property(x => x.Severity).HasConversion<string>();
            e.Property(x => x.Status).HasConversion<string>();
            e.Property(x => x.Automatability).HasConversion<string>();
        });

        b.Entity<GenerationRecord>(e =>
        {
            e.ToTable("generations");
            e.HasOne(x => x.Finding).WithMany(x => x.Generations)
                .HasForeignKey(x => x.FindingId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.FindingId, x.CreatedAt });
            e.Property(x => x.ParametersJson).HasColumnType("jsonb");
        });

        b.Entity<ValidationRunRecord>(e =>
        {
            e.ToTable("validation_runs");
            e.HasOne(x => x.Generation).WithMany(x => x.ValidationRuns)
                .HasForeignKey(x => x.GenerationId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.GenerationId, x.StartedAt });
            e.Property(x => x.Outcome).HasConversion<string>();
            e.Property(x => x.EvidenceJson).HasColumnType("jsonb");
        });
    }
}
