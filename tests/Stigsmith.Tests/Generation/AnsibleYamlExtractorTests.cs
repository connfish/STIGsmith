using Stigsmith.Generation.Prompting;

namespace Stigsmith.Tests.Generation;

public class AnsibleYamlExtractorTests
{
    private const string GoodTask = """
        - name: "RHEL-08-010550 | PATCH | Root SSH logon"
          ansible.builtin.lineinfile:
            path: /etc/ssh/sshd_config
            regexp: '^(?i)\s*PermitRootLogin'
            line: PermitRootLogin no
          notify: restart sshd
          tags:
            - RHEL-08-010550
        """;

    [Fact]
    public void Accepts_bare_task_yaml()
    {
        var result = AnsibleYamlExtractor.Extract(GoodTask);

        result.Kind.ShouldBe(GeneratedYamlKind.Tasks);
        result.IsUsable.ShouldBeTrue();
        result.TaskNames.ShouldBe(["RHEL-08-010550 | PATCH | Root SSH logon"]);
        result.Yaml.ShouldContain("PermitRootLogin no");
    }

    [Fact]
    public void Accepts_a_document_marker()
    {
        AnsibleYamlExtractor.Extract("---\n" + GoodTask).Kind.ShouldBe(GeneratedYamlKind.Tasks);
    }

    /// <summary>
    /// The prompt asks for no fence, and models mostly comply. Discarding an otherwise correct generation over
    /// a formatting habit would just mean re-running the model for the same content in different packaging.
    /// </summary>
    [Fact]
    public void Strips_a_code_fence()
    {
        var result = AnsibleYamlExtractor.Extract("```yaml\n" + GoodTask + "\n```");

        result.Kind.ShouldBe(GeneratedYamlKind.Tasks);
        result.Yaml.ShouldNotContain("```");
    }

    [Fact]
    public void Strips_leading_prose_and_trailing_commentary()
    {
        var response = "Here are the tasks that apply the fix:\n\n" + GoodTask
            + "\n\nLet me know if you need anything else!";

        var result = AnsibleYamlExtractor.Extract(response);

        result.Kind.ShouldBe(GeneratedYamlKind.Tasks);
        result.Yaml.ShouldNotContain("Here are the tasks");
        result.Yaml.ShouldNotContain("Let me know");
        result.Yaml.ShouldContain("PermitRootLogin no");
    }

    [Fact]
    public void Reads_multiple_tasks()
    {
        var result = AnsibleYamlExtractor.Extract("""
            - name: Install firewalld
              ansible.builtin.dnf:
                name: firewalld
                state: present
            - name: Enable firewalld
              ansible.builtin.systemd_service:
                name: firewalld
                enabled: true
                state: started
            """);

        result.Kind.ShouldBe(GeneratedYamlKind.Tasks);
        result.TaskNames.Count.ShouldBe(2);
    }

    /// <summary>
    /// A model saying "I cannot express this idempotently" is a correct answer and must be distinguishable
    /// from a failure, so the validation loop does not spend a repair attempt on it.
    /// </summary>
    [Fact]
    public void Recognises_the_cannot_automate_answer()
    {
        var result = AnsibleYamlExtractor.Extract(
            "# cannot-automate: the fix requires a password that cannot be supplied non-interactively");

        result.Kind.ShouldBe(GeneratedYamlKind.CannotAutomate);
        result.IsUsable.ShouldBeFalse();
        result.Message.ShouldContain("password");
    }

    [Fact]
    public void Recognises_cannot_automate_even_with_a_preamble()
    {
        var result = AnsibleYamlExtractor.Extract(
            "I looked at this fix and it needs interactive input.\n\n# cannot-automate: interactive prompt required");

        result.Kind.ShouldBe(GeneratedYamlKind.CannotAutomate);
        result.Message.ShouldBe("interactive prompt required");
    }

    [Theory]
    [InlineData("", "returned nothing")]
    [InlineData("   \n  ", "returned nothing")]
    [InlineData("I am unable to help with that request.", "No YAML found")]
    [InlineData("- name: unclosed\n  ansible.builtin.copy:\n   content: \"oops\n  bad: [ 1, 2", "not valid YAML")]
    public void Rejects_a_response_with_no_usable_yaml(string response, string expectedMessage)
    {
        var result = AnsibleYamlExtractor.Extract(response);

        result.Kind.ShouldBe(GeneratedYamlKind.Invalid);
        result.Message.ShouldContain(expectedMessage);
    }

    /// <summary>
    /// A play (a mapping with `hosts:` and `tasks:`) is not what was asked for. Accepting it would put a
    /// hosts line into the operator's role, which is both wrong and a constraint 3 hazard.
    /// </summary>
    [Fact]
    public void Rejects_a_playbook_instead_of_a_task_list()
    {
        var result = AnsibleYamlExtractor.Extract("""
            hosts: all
            become: true
            tasks:
              - name: Root SSH logon
                ansible.builtin.lineinfile:
                  path: /etc/ssh/sshd_config
                  line: PermitRootLogin no
            """);

        result.Kind.ShouldBe(GeneratedYamlKind.Invalid);
        result.Message.ShouldContain("not a list of tasks");
    }

    [Fact]
    public void Rejects_an_empty_list()
    {
        AnsibleYamlExtractor.Extract("[]").Kind.ShouldBe(GeneratedYamlKind.Invalid);
        AnsibleYamlExtractor.Extract("[]").Message.ShouldContain("applies no fix");
    }

    [Fact]
    public void Rejects_a_list_of_scalars()
    {
        var result = AnsibleYamlExtractor.Extract("- install firewalld\n- enable firewalld\n");

        result.Kind.ShouldBe(GeneratedYamlKind.Invalid);
        result.Message.ShouldContain("not a task mapping");
    }

    /// <summary>It reports a problem; it does not repair one. M6 feeds the message back for a repair attempt.</summary>
    [Fact]
    public void Does_not_attempt_to_repair_broken_yaml()
    {
        var broken = "- name: missing colon\n  ansible.builtin.lineinfile\n    path: /etc/issue\n";

        var result = AnsibleYamlExtractor.Extract(broken);

        result.Kind.ShouldBe(GeneratedYamlKind.Invalid);
        result.Message.ShouldNotBeNullOrWhiteSpace();
    }
}
