using Stigsmith.Generation.Conventions;
using Stigsmith.Tests.Support;

namespace Stigsmith.Tests.Generation;

public class RoleIndexerTests
{
    private static RoleIndex Index() => new AnsibleRoleIndexer().Index(new ConventionRoleOptions
    {
        Path = TestEnvironment.ExampleRolePath,
    });

    [Fact]
    public void Indexes_every_task_in_the_example_role()
    {
        var index = Index();

        index.UnavailableReason.ShouldBeNull();
        // 16 real tasks across cat1/cat2/cat3 plus 5 handlers. The three import_tasks entries in
        // tasks/main.yml are plumbing and are deliberately not indexed.
        index.Tasks.Count.ShouldBe(21);
        index.Tasks.ShouldAllBe(t => t.RawYaml.Length > 0);
        index.SkippedFiles.ShouldBeEmpty();
    }

    [Fact]
    public void Extracts_per_task_metadata()
    {
        var task = Index().Tasks.Single(t => t.StigVersionIds.Contains("RHEL-08-010550"));

        task.Name.ShouldContain("must not permit direct logons to root");
        task.Module.ShouldBe("ansible.builtin.lineinfile");
        task.NotifiedHandlers.ShouldBe(["restart sshd"]);
        task.WhenGuards.ShouldBe(["stigsmith_rhel8_rule_230296"]);
        task.Tags.ShouldBe(["RHEL-08-010550", "V-230296", "CAT2", "medium", "sshd"]);
        task.Variables.ShouldContain("stigsmith_rhel8_sshd_config_path");
        task.Variables.ShouldContain("stigsmith_rhel8_rule_230296");
        task.RuleIds.ShouldContain("V-230296");
        task.NumericRuleIds.ShouldContain("230296");
        task.SourceFile.ShouldBe(Path.Combine("tasks", "cat2.yml"));
        task.SourceLine.ShouldBeGreaterThan(0);
    }

    /// <summary>
    /// The raw YAML is what gets shown to the model, so it has to be a complete, copyable task — leading
    /// list marker included — in the role's own formatting rather than re-serialized.
    /// </summary>
    [Fact]
    public void Raw_yaml_is_the_task_verbatim_and_starts_at_the_list_marker()
    {
        var task = Index().Tasks.Single(t => t.StigVersionIds.Contains("RHEL-08-010550"));

        task.RawYaml.TrimStart().ShouldStartWith("- name:");
        task.RawYaml.ShouldContain("validate: /usr/sbin/sshd -t -f %s");
        task.RawYaml.ShouldContain("notify: restart sshd");
        // Quoting style preserved: the role writes the name in double quotes.
        task.RawYaml.ShouldContain("\"RHEL-08-010550 | PATCH |");
    }

    [Fact]
    public void Handles_a_task_with_a_loop_and_a_block_scalar()
    {
        var index = Index();

        var looped = index.Tasks.Single(t => t.StigVersionIds.Contains("RHEL-08-030620"));
        looped.Module.ShouldBe("ansible.builtin.file");
        looped.RawYaml.ShouldContain("loop_control:");
        looped.Variables.ShouldContain("audit_tool");

        var block = index.Tasks.Single(t => t.StigVersionIds.Contains("RHEL-08-020060"));
        block.Module.ShouldBe("ansible.builtin.blockinfile");
        block.RawYaml.ShouldContain("idle-delay=uint32");
    }

    [Fact]
    public void Indexes_handlers_as_tasks_so_their_shape_is_available_too()
    {
        var index = Index();

        var handlers = index.Tasks.Where(t => t.SourceFile.Contains("handlers")).ToArray();

        handlers.Length.ShouldBe(5);
        handlers.Select(h => h.Name).ShouldContain("restart sshd");
        handlers.Select(h => h.Name).ShouldContain("reload sysctl");
    }

    [Fact]
    public void Reports_an_unconfigured_or_missing_role_rather_than_throwing()
    {
        new AnsibleRoleIndexer().Index(new ConventionRoleOptions { Path = null })
            .UnavailableReason.ShouldNotBeNull().ShouldContain("No convention role path is configured");

        new AnsibleRoleIndexer().Index(new ConventionRoleOptions { Path = "/no/such/role" })
            .UnavailableReason.ShouldNotBeNull().ShouldContain("does not exist");

        var empty = new AnsibleRoleIndexer().Index(new ConventionRoleOptions
        {
            Path = TestEnvironment.ExampleRolePath,
            TaskDirectories = ["nonexistent-dir"],
        });
        empty.UnavailableReason.ShouldNotBeNull().ShouldContain("No task files found");
        empty.IsEmpty.ShouldBeTrue();
    }

    /// <summary>
    /// A role with one unparseable file must still yield an index. An operator whose role has a single
    /// Jinja-templated task file should not silently lose convention retrieval altogether.
    /// </summary>
    [Fact]
    public void One_unparseable_file_does_not_abort_the_index()
    {
        var temp = Directory.CreateTempSubdirectory("stigsmith-role-");
        try
        {
            var tasks = Directory.CreateDirectory(Path.Combine(temp.FullName, "tasks"));
            File.WriteAllText(Path.Combine(tasks.FullName, "good.yml"),
                "---\n- name: \"RHEL-08-010550 | PATCH | Root SSH\"\n  ansible.builtin.lineinfile:\n"
                + "    path: /etc/ssh/sshd_config\n    line: PermitRootLogin no\n  tags:\n    - RHEL-08-010550\n");
            File.WriteAllText(Path.Combine(tasks.FullName, "broken.yml"),
                "---\n- name: broken\n  ansible.builtin.copy:\n   content: \"unclosed\n  bad: [ indentation\n");

            var index = new AnsibleRoleIndexer().Index(new ConventionRoleOptions { Path = temp.FullName });

            index.Tasks.Count.ShouldBe(1);
            index.SkippedFiles.Count.ShouldBe(1);
            index.SkippedFiles[0].ShouldContain("broken.yml");
        }
        finally
        {
            temp.Delete(recursive: true);
        }
    }

    [Fact]
    public void Identifies_the_module_even_when_a_task_keyword_is_unfamiliar()
    {
        var tasks = AnsibleRoleIndexer.ParseFile(
            "---\n- name: future keyword\n  some_future_keyword: yes\n  ansible.builtin.copy:\n"
            + "    dest: /etc/thing\n    content: x\n", "tasks/future.yml").ToArray();

        tasks.Single().Module.ShouldBe("ansible.builtin.copy");
    }
}

public class RoleConventionsTests
{
    private static RoleConventions Conventions() =>
        new AnsibleRoleIndexer().Index(new ConventionRoleOptions { Path = TestEnvironment.ExampleRolePath })
            .Conventions;

    /// <summary>
    /// These are the house conventions the example role deliberately makes distinctive. Inferring them is
    /// what lets the prompt state them outright instead of hoping the model notices them in the examples.
    /// </summary>
    [Fact]
    public void Infers_the_house_style_of_the_example_role()
    {
        var conventions = Conventions();

        conventions.VariablePrefix.ShouldBe("stigsmith_rhel8_");
        conventions.RuleToggleTemplate.ShouldBe("stigsmith_rhel8_rule_<vuln number>");
        conventions.UsesFullyQualifiedModules.ShouldBeTrue();
        conventions.TagsIncludeStigVersionId.ShouldBeTrue();
        conventions.TagsIncludeVulnId.ShouldBeTrue();
        conventions.CommonModules[0].ShouldBe("ansible.builtin.lineinfile");
        conventions.HandlerNames.ShouldContain("restart sshd");
        conventions.HandlerNames.ShouldContain("reload sysctl");
        conventions.CommonTags.ShouldContain("CAT2");
        conventions.CommonTags.ShouldContain("medium");
    }

    /// <summary>
    /// The prefix must stop at an underscore. The raw longest common prefix of
    /// stigsmith_rhel8_rule_230296 and stigsmith_rhel8_rule_230244 is "stigsmith_rhel8_rule_2302", which
    /// is not a convention and would be nonsense to put in a prompt.
    /// </summary>
    [Fact]
    public void Variable_prefix_stops_at_a_word_boundary()
    {
        Conventions().VariablePrefix!.ShouldEndWith("_");
        Conventions().VariablePrefix.ShouldNotBe("stigsmith_rhel8_rule_2302");
    }

    [Fact]
    public void Describes_itself_for_the_prompt()
    {
        var description = Conventions().Describe();

        description.ShouldContain("stigsmith_rhel8_");
        description.ShouldContain("fully qualified");
        description.ShouldContain("Do not invent a handler name");
        description.ShouldContain("restart sshd");
    }

    [Fact]
    public void An_empty_role_describes_nothing_rather_than_asserting_conventions()
    {
        RoleConventions.Infer([]).ShouldBeSameAs(RoleConventions.None);
        RoleConventions.None.Describe().ShouldBeEmpty();
    }
}
