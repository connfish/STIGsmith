using Microsoft.EntityFrameworkCore;
using Stigsmith.Api.Persistence;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests;

public class SolutionSmokeTests
{
    /// <summary>
    /// Builds the EF model without touching a database. Catches mapping mistakes — a bad index, a
    /// relationship with no key, a jsonb column on a non-string property — in CI on a runner with no
    /// Postgres, which is where those mistakes would otherwise surface only at first migration.
    /// </summary>
    [Fact]
    public void Ef_model_is_valid()
    {
        var options = new DbContextOptionsBuilder<StigsmithDbContext>()
            .UseNpgsql("Host=unused;Database=unused;Username=unused;Password=unused")
            .Options;
        using var db = new StigsmithDbContext(options);

        var entities = db.Model.GetEntityTypes().Select(e => e.GetTableName()).ToList();

        entities.ShouldContain("checklists");
        entities.ShouldContain("findings");
        entities.ShouldContain("generations");
        entities.ShouldContain("validation_runs");
    }

    [Fact]
    public void Repository_root_resolves_from_test_output()
    {
        File.Exists(Path.Combine(TestEnvironment.RepoRoot, "Stigsmith.slnx")).ShouldBeTrue();
    }
}
