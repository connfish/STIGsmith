using System.Text;
using System.Text.RegularExpressions;
using Stigsmith.Checklists.Model;

namespace Stigsmith.Validation;

/// <summary>What a verification attempt concluded about one rule.</summary>
/// <param name="Reason">One sentence on how the verdict was reached, for the evidence.</param>
public sealed record VerificationResult(
    ComplianceVerifierKind Kind,
    string Status,
    string Command,
    ExecResult Output,
    string Reason = "")
{
    /// <summary>The only status that lets a remediation be called validated.</summary>
    public bool Passed => Status.Equals("pass", StringComparison.OrdinalIgnoreCase);

    /// <summary>The status with its reason, as the evidence prints it: <c>fail (output does not contain …)</c>.</summary>
    public string Describe => Reason.Length > 0 ? $"{Status} ({Reason})" : Status;

    public static VerificationResult NotVerified(string why) =>
        new(ComplianceVerifierKind.None, "unknown", "", new ExecResult(-1, "", why), why);
}

/// <summary>How the check-content verifier reads the command's output.</summary>
public enum CheckPolarity
{
    /// <summary>The check shows what compliant output looks like; every shown line must appear in the output.</summary>
    ExpectedOutput,

    /// <summary>"If the package is installed, this is a finding": any output at all is a failure.</summary>
    Negative,

    /// <summary>Nothing better to go on: a zero exit is a pass.</summary>
    ExitCode,
}

/// <summary>The runnable part of a rule's check content: the command, the compliant output it shows, and how to read the result.</summary>
public sealed record CheckSpec(string Command, IReadOnlyList<string> ExpectedLines, CheckPolarity Polarity);

/// <summary>
/// Re-checks whether a rule passes, inside the sandbox, after remediation has been applied.
/// </summary>
/// <remarks>
/// <para>
/// Step 3 of the loop, and the one that makes the rest mean anything: lint and a clean apply only prove the YAML
/// ran, not that it fixed the finding.
/// </para>
/// <para>
/// Two strategies, and which one ran is recorded, because they are not worth the same:
/// </para>
/// <list type="number">
/// <item><b>oscap</b> — a real SCAP scan of that one rule against an installed datastream. The primary path, and
/// the one the milestone asks for.</item>
/// <item><b>check content</b> — DISA's own verification command, extracted from the rule's <c>check content</c> and
/// run as a shell test. Used when oscap has no definition for the rule, which covers both synthetic fixtures and
/// the many real STIG rules whose manual benchmark carries a command but no OVAL.</item>
/// </list>
/// <para>
/// An ISSO reading the evidence needs to know which produced the verdict, so <see cref="VerificationResult.Kind"/>
/// is part of the record rather than an implementation detail.
/// </para>
/// </remarks>
public sealed partial class ComplianceVerifier(ValidationOptions options)
{
    /// <summary>
    /// A command line in DISA check content. They are written as <c>$ sudo grep -i permitrootlogin /etc/…</c> or with
    /// a bare <c>#</c> prompt.
    /// </summary>
    [GeneratedRegex(@"^[ \t]*[$#][ \t]+(?<command>\S.*)$", RegexOptions.Multiline)]
    private static partial Regex PromptedCommand();

    public async Task<VerificationResult> VerifyAsync(
        IValidationSession session, RuleContent rule, CancellationToken cancellationToken = default)
    {
        if (options.PreferOscap)
        {
            var oscap = await TryOscapAsync(session, rule, cancellationToken);
            if (oscap is not null) return oscap;
        }

        return await VerifyByCheckContentAsync(session, rule, cancellationToken);
    }

    /// <summary>
    /// Runs <c>oscap xccdf eval</c> for this one rule. Returns null when oscap or the datastream is unavailable, or
    /// when the datastream has no rule for this STIG id — all of which mean "use the other strategy", not "the rule
    /// failed".
    /// </summary>
    /// <remarks>
    /// The datastream is SCAP Security Guide content, whose rules are named <c>xccdf_org.ssgproject.content_rule_…</c>
    /// and carry the DISA id (<c>RHEL-08-010370</c>) only as a <c>reference</c> element. So the DISA id is resolved to
    /// the SSG rule id with an XPath query inside the container first; without that step no rule ever matches and
    /// every verification quietly falls back to check content, which is exactly what happened before this existed.
    /// The STIG id is re-derived through <see cref="RuleIdentifiers.StigVersion"/> before it goes anywhere near a
    /// shell, because it arrived inside an uploaded checklist.
    /// </remarks>
    private async Task<VerificationResult?> TryOscapAsync(
        IValidationSession session, RuleContent rule, CancellationToken cancellationToken)
    {
        var stigId = RuleIdentifiers.StigVersion(rule.RuleVersion);
        if (stigId is null) return null;

        var probe = await session.ExecAsync(
            $"command -v oscap >/dev/null 2>&1 && command -v xmllint >/dev/null 2>&1 "
            + $"&& test -f {options.ScapDatastreamPath} && echo ready",
            cancellationToken);
        if (!probe.Stdout.Contains("ready", StringComparison.Ordinal)) return null;

        var lookup = await session.ExecAsync(
            "xmllint --xpath 'string(//*[local-name()=\"Rule\"][*[local-name()=\"reference\"][text()=\""
            + stigId + "\"]]/@id)' " + options.ScapDatastreamPath + " 2>/dev/null",
            cancellationToken);
        var ssgRuleId = lookup.Stdout.Trim();
        if (!SsgRuleId().IsMatch(ssgRuleId)) return null;

        var command =
            $"oscap xccdf eval --profile {options.ScapProfile} --rule {ssgRuleId} "
            + $"--results /tmp/stigsmith-results.xml {options.ScapDatastreamPath} 2>&1 || true";

        var result = await session.ExecAsync(command, cancellationToken);
        var status = ParseOscapStatus(result.Combined);

        // "notchecked" and "notselected" mean oscap had nothing to say about this rule. "notapplicable" is what SSG
        // reports inside a container for every rule it tags with its `machine` platform — most host-configuration
        // rules — so it means the same thing here. All fall through rather than recording a verdict oscap did not give.
        if (status is null or "notchecked" or "notselected" or "notapplicable") return null;

        return new VerificationResult(ComplianceVerifierKind.Oscap, status, command, result);
    }

    /// <summary>The only shape an SSG rule id takes, so nothing else from the lookup reaches the eval command.</summary>
    [GeneratedRegex(@"^xccdf_org\.ssgproject\.content_rule_[A-Za-z0-9_.\-]+$")]
    private static partial Regex SsgRuleId();

    /// <summary>
    /// Runs the command DISA's check content prescribes and reads the output the way the check content says to.
    /// </summary>
    /// <remarks>
    /// Deliberately conservative. Only a read-only prompted command is run, <c>sudo</c> is stripped (the container
    /// runs as root), and check content with no runnable command yields "unknown" rather than a guess. A wrong pass
    /// here would be worse than no verification, because it would be evidence of something that did not happen.
    /// </remarks>
    private async Task<VerificationResult> VerifyByCheckContentAsync(
        IValidationSession session, RuleContent rule, CancellationToken cancellationToken)
    {
        var spec = ExtractCheck(rule.CheckContent);
        if (spec is null)
            return VerificationResult.NotVerified(
                "The rule's check content contains no runnable read-only command, and oscap had no definition for "
                + "it. This remediation cannot be automatically verified.");

        var result = await session.ExecAsync(spec.Command, cancellationToken);
        var (status, reason) = Judge(spec, result);
        return new VerificationResult(ComplianceVerifierKind.CheckContent, status, spec.Command, result, reason);
    }

    /// <summary>The first runnable read-only command in DISA check content, or null when there is none.</summary>
    public static string? ExtractCheckCommand(string? checkContent) => ExtractCheck(checkContent)?.Command;

    /// <summary>
    /// Reads DISA check content the way an assessor does: the prompted command, the compliant output shown under
    /// it, and the "this is a finding" sentence that says which way to read it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The exit code alone was the first version of this, and a live run showed both of its failure modes: a
    /// <c>grep</c> that matches the commented default line in a stock config file exits zero, so a rule passed
    /// before anything was applied; and "if the package is installed, this is a finding" passes exactly when the
    /// command <em>fails</em>. Hence three readings. Where the check shows the compliant output, every shown line
    /// must appear in the real output. Where it shows none and the finding sentence says that output is the
    /// finding, any output fails. Otherwise a zero exit passes, which is the weakest reading and is recorded as such.
    /// </para>
    /// <para>
    /// Shown output that is plainly an example rather than a requirement — a package listing with a version, a
    /// password hash, a mount line, a permissions listing — is not matched literally; without it the rule falls to
    /// the sentence reading. That errs toward "fail" or "unknown", never toward a pass the output does not support.
    /// </para>
    /// </remarks>
    public static CheckSpec? ExtractCheck(string? checkContent)
    {
        if (string.IsNullOrWhiteSpace(checkContent)) return null;
        var lines = checkContent.ReplaceLineEndings("\n").Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var prompt = PromptedCommand().Match(lines[i]);
            if (!prompt.Success) continue;

            var command = prompt.Groups["command"].Value.Trim();
            if (command.StartsWith("sudo ", StringComparison.Ordinal)) command = command[5..].TrimStart();
            // Refuse anything that could change the system. A verification step that remediates would make the
            // re-scan pass by its own action, which is the most dangerous possible bug in this loop.
            if (command.Length == 0 || !IsReadOnly(command)) continue;

            var expected = new List<string>();
            for (var j = i + 1; j < lines.Length; j++)
            {
                var line = lines[j].Trim();
                if (line.Length == 0 || PromptedCommand().IsMatch(lines[j]) || LooksLikeProse(line)) break;
                if (!Illustrative().IsMatch(line)) expected.Add(line);
            }

            var polarity = expected.Count > 0 ? CheckPolarity.ExpectedOutput
                : FindingSentences(checkContent).Any(IsNegativeFinding) ? CheckPolarity.Negative
                : CheckPolarity.ExitCode;

            return new CheckSpec(command, expected, polarity);
        }

        return null;
    }

    /// <summary>Decides the verdict for a check that ran, and says why in one sentence.</summary>
    public static (string Status, string Reason) Judge(CheckSpec spec, ExecResult result)
    {
        var pipeline = SplitPipeline(NullRedirect().Replace(spec.Command, " "));
        var first = pipeline?.FirstOrDefault()?.FirstOrDefault() ?? "";
        var last = pipeline?.LastOrDefault()?.FirstOrDefault() ?? "";

        if (result.ExitCode is 126 or 127)
            return ("unknown", $"the check command could not run (exit {result.ExitCode})");
        if (last is "grep" or "egrep" or "fgrep" or "zgrep" && result.ExitCode == 2 && string.IsNullOrWhiteSpace(result.Stdout))
            return ("unknown", "grep reported an error rather than a result (exit 2)");

        var actual = result.Stdout.ReplaceLineEndings("\n").Split('\n')
            .Select(Normalize)
            .Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith(';'))
            .ToArray();

        switch (spec.Polarity)
        {
            case CheckPolarity.ExpectedOutput:
                var missing = spec.ExpectedLines.Where(e => !actual.Any(a => a.Contains(Normalize(e), StringComparison.Ordinal))).ToArray();
                return missing.Length == 0
                    ? ("pass", $"the output contains {Quote(spec.ExpectedLines)}")
                    : ("fail", $"the output does not contain {Quote(missing)}");

            case CheckPolarity.Negative:
                return result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Stdout)
                    ? ("pass", "the command returned nothing, and the check says any result is a finding")
                    : ("fail", "the command returned a result, which the check says is a finding");

            default:
                if (first == "find" && string.IsNullOrWhiteSpace(result.Stdout))
                    return ("fail", "find returned nothing, and find exits zero whether or not it finds anything");
                return result.Succeeded
                    ? ("pass", "the command exited zero; the check shows no output to compare against")
                    : ("fail", $"the command exited {result.ExitCode}");
        }
    }

    /// <summary>Lower-cased, whitespace-collapsed, and without the <c>/path:</c> prefix grep adds when given several files.</summary>
    private static string Normalize(string line) =>
        Whitespace().Replace(GrepFilePrefix().Replace(line.Trim(), ""), " ").ToLowerInvariant();

    private static string Quote(IEnumerable<string> lines) => string.Join(", ", lines.Select(l => $"'{l}'"));

    /// <summary>A line of explanation rather than output, which DISA sometimes puts directly under the command.</summary>
    private static bool LooksLikeProse(string line) =>
        line.StartsWith("If ", StringComparison.Ordinal) || line.StartsWith("Note", StringComparison.Ordinal)
        || line.Contains("this is a finding", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<string> FindingSentences(string text) =>
        SentenceBreak().Split(text).Where(s => s.Contains("this is a finding", StringComparison.OrdinalIgnoreCase));

    /// <summary>"If X is installed / is found / returns output, this is a finding" — with no "not" in it.</summary>
    private static bool IsNegativeFinding(string sentence) =>
        NegativeFindingSignal().IsMatch(sentence) && !NegationSignal().IsMatch(sentence);

    [GeneratedRegex(@"(?<=[.:!?])\s+|\n\s*\n")]
    private static partial Regex SentenceBreak();

    [GeneratedRegex(@"\b(?:is|are)\s+(?:installed|found|present|returned|listed|displayed|enabled|running|configured|loaded|active)\b|\bfound to be\b|\bany\s+(?:output|results?|lines?|files?|packages?|accounts?|entries|interfaces?)\b|\breturns?\s+(?:any\s+)?(?:output|results?|lines?)\b|\bexists?\b|\bhas\s+\S+\s+installed\b", RegexOptions.IgnoreCase)]
    private static partial Regex NegativeFindingSignal();

    [GeneratedRegex(@"\b(?:not|no|missing|unless|other than|less than|more than|does not|is not|are not|without|absent|fails?|empty)\b", RegexOptions.IgnoreCase)]
    private static partial Regex NegationSignal();

    /// <summary>
    /// Shown output that is an example, not a requirement: a permissions listing, a password hash, a package listing
    /// with a version, a mount line, a boot-loader line, a truncated value, or a versioned package name.
    /// </summary>
    [GeneratedRegex(@"^[-dlcbps][-rwxsStT]{9}[.+]?\s|\$\d\$|^\S+\.(?:x86_64|noarch|aarch64|i686)\s+\S+\s+@|^/dev/|^kernelopts=|\.\.\.$|\d+\.\d+-\d+\.el\d")]
    private static partial Regex Illustrative();

    [GeneratedRegex(@"^/[^:\s]+:")]
    private static partial Regex GrepFilePrefix();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    /// <summary>
    /// Whether this invocation can be run as a verification step.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An allow-list, not a deny-list. Check content is attacker-shaped input — it arrives inside an uploaded
    /// checklist — and a verifier that can be talked into changing the container would then re-scan its own change
    /// and report a pass. An earlier version enumerated mutating verbs and was bypassed by anything it had not heard
    /// of: <c>python3 -c</c>, <c>dd</c>, <c>ln</c>, <c>find -delete</c>, or a <c>;</c> after a harmless command.
    /// </para>
    /// <para>
    /// So the rule is: every command in the pipeline must be one known to be read-only, invoked in a read-only way,
    /// and nothing may chain, substitute, background, or redirect. What that refuses is reported as "cannot verify",
    /// which is the honest answer and far better than a false pass. The list is meant to grow as real check content
    /// turns up read-only commands it lacks; a rejected command is visible in the evidence as an unverified rule.
    /// </para>
    /// </remarks>
    public static bool IsReadOnly(string command)
    {
        // The two redirections DISA uses to silence noise are harmless; any other redirection is refused below.
        var segments = SplitPipeline(NullRedirect().Replace(command, " "));
        return segments is { Count: > 0 } && segments.All(ReadOnlyInvocation);
    }

    /// <summary><c>2&gt;/dev/null</c>, <c>2&gt;&amp;1</c>, <c>&gt;/dev/null</c>, <c>&amp;&gt;/dev/null</c>.</summary>
    [GeneratedRegex(@"\s*[12&]?>\s*(?:/dev/null|&\s*[12])\b")]
    private static partial Regex NullRedirect();

    /// <summary>
    /// Splits at unquoted <c>|</c> into segments of shell words with their quoting removed — the words the binary will
    /// actually receive, which is what the checks below must run against. A flag hidden in quotes (<c>'-F'</c>,
    /// <c>$'-out'</c>) reaches the binary as the bare flag, so classifying the quoted text was a bypass.
    /// </summary>
    /// <remarks>
    /// Null for anything the verifier refuses to hand to a shell: chaining, backgrounding, grouping, any redirection
    /// other than the silenced ones, any expansion at all (<c>$</c> outside single quotes, backticks, process
    /// substitution), and an unbalanced quote. Only what is decoded here is allowed, so the parser and the shell agree
    /// on every accepted command: single quotes are literal, double quotes are literal apart from backslash escapes
    /// and may not contain an expansion, and a backslash escapes the next character.
    /// </remarks>
    private static List<List<string>>? SplitPipeline(string command)
    {
        var segments = new List<List<string>>();
        var words = new List<string>();
        var word = new StringBuilder();
        var inWord = false;

        void EndWord()
        {
            if (!inWord) return;
            words.Add(word.ToString());
            word.Clear();
            inWord = false;
        }

        for (var i = 0; i < command.Length; i++)
        {
            var c = command[i];
            switch (c)
            {
                case '\'':
                {
                    var close = command.IndexOf('\'', i + 1);
                    if (close < 0) return null;
                    inWord = true;
                    word.Append(command, i + 1, close - i - 1);
                    i = close;
                    break;
                }
                case '"':
                {
                    inWord = true;
                    i++;
                    while (i < command.Length && command[i] != '"')
                    {
                        var d = command[i];
                        if (d is '$' or '`') return null;
                        if (d == '\\' && i + 1 < command.Length && command[i + 1] is '"' or '\\' or '$' or '`') d = command[++i];
                        word.Append(d);
                        i++;
                    }
                    if (i >= command.Length) return null;
                    break;
                }
                case '\\':
                    if (i + 1 >= command.Length) return null;
                    inWord = true;
                    word.Append(command[++i]);
                    break;
                case '|':
                    if (i + 1 < command.Length && command[i + 1] == '|') return null;
                    EndWord();
                    segments.Add(words);
                    words = [];
                    break;
                case ' ' or '\t':
                    EndWord();
                    break;
                case ';' or '&' or '>' or '<' or '`' or '$' or '(' or ')' or '\n' or '\r':
                    return null;
                default:
                    inWord = true;
                    word.Append(c);
                    break;
            }
        }

        EndWord();
        segments.Add(words);
        return segments;
    }

    /// <summary>Commands that cannot change anything however they are called, given that redirection is already refused.</summary>
    private static readonly HashSet<string> AlwaysReadOnly = new(StringComparer.Ordinal)
    {
        "grep", "egrep", "fgrep", "zgrep", "cat", "ls", "stat", "head", "tail", "wc", "sort", "uniq", "cut", "tr",
        "diff", "cmp", "comm", "file", "strings", "md5sum", "sha256sum", "sha512sum", "readlink", "realpath",
        "basename", "dirname", "namei", "test", "[", "echo", "printf", "true", "false", "getent", "id", "groups",
        "whoami", "hostname", "uname", "date", "df", "du", "findmnt", "lsblk", "blkid", "ps", "pgrep", "ss",
        "netstat", "lsmod", "lsattr", "getfacl", "getcap", "lscpu", "dmesg", "sestatus", "getenforce", "getsebool",
        "matchpathcon", "ausearch", "aureport", "journalctl", "last", "lastb", "lastlog", "who", "w", "locale",
        "printenv", "rpmquery", "sshd_config_check",
    };

    /// <summary>
    /// One pipeline segment. Binaries that only read are allowed outright; binaries that read or write depending on
    /// the invocation are allowed only in their read-only forms, matched on the sub-command or flag that decides it.
    /// </summary>
    private static bool ReadOnlyInvocation(List<string> words)
    {
        if (words.Count == 0) return false;

        var binary = words[0][(words[0].LastIndexOf('/') + 1)..];
        var args = words[1..].ToArray();
        var rest = string.Join(' ', args);

        bool AnyArg(params string[] prefixes) =>
            args.Any(a => prefixes.Any(p => a.StartsWith(p, StringComparison.Ordinal)));
        bool FirstArgIn(params string[] verbs) => args.Length > 0 && verbs.Contains(args[0], StringComparer.Ordinal);
        bool AllArgsStartWith(params string[] prefixes) =>
            args.Length > 0 && args.All(a => prefixes.Any(p => a.StartsWith(p, StringComparison.Ordinal)));

        if (AlwaysReadOnly.Contains(binary)) return true;

        return binary switch
        {
            // awk programs can shell out and write files; refuse those forms rather than the binary.
            "awk" or "gawk" or "mawk" => !rest.Contains("system", StringComparison.Ordinal)
                                         && !rest.Contains("getline", StringComparison.Ordinal)
                                         && !rest.Contains('>') && !rest.Contains('|'),
            "find" => FindIsReadOnly(args),
            "systemctl" => FirstArgIn("is-enabled", "is-active", "is-failed", "is-system-running", "status", "show",
                "cat", "list-units", "list-unit-files", "list-dependencies", "list-timers", "list-sockets", "get-default"),
            "sysctl" => !AnyArg("-w", "--write", "-p", "--load", "--system") && !rest.Contains('='),
            "rpm" => args.Length > 0 && (args[0].StartsWith("-q", StringComparison.Ordinal)
                                         || args[0].StartsWith("-V", StringComparison.Ordinal)
                                         || args[0] is "--query" or "--verify" or "-K" or "--checksig"),
            "rpmkeys" => FirstArgIn("--checksig", "-K"),
            "yum" or "dnf" => FirstArgIn("list", "info", "repolist", "repoquery", "check-update", "provides",
                "search", "updateinfo", "grouplist", "groupinfo"),
            "firewall-cmd" => AllArgsStartWith("--list", "--get", "--query", "--info", "--state", "--permanent",
                "--check-config", "--zone=", "--policy="),
            "nmcli" => args.Length switch
            {
                0 => true,
                1 => args[0] is "radio" or "general" or "g" or "networking" or "device" or "dev" or "connection" or "con" or "c",
                _ => (args[0], args[1]) is ("device" or "dev", "status" or "show" or "wifi")
                                          or ("connection" or "con" or "c", "show")
                                          or ("general" or "g", "status" or "hostname")
                                          or ("radio", "wifi" or "all" or "wwan") && args.Length == 2,
            },
            "grubby" => AllArgsStartWith("--info"),
            "grub2-editenv" or "grub-editenv" => args.Contains("list") && !AnyArg("set", "unset", "create"),
            "fips-mode-setup" => FirstArgIn("--check", "--is-enabled"),
            "update-crypto-policies" => FirstArgIn("--show", "--is-applied"),
            "authselect" => FirstArgIn("current", "list", "list-features", "check", "show"),
            "dconf" => FirstArgIn("read", "dump", "list"),
            "gsettings" => FirstArgIn("get", "list-keys", "list-schemas", "list-recursively", "list-children", "range", "describe"),
            "sshd" => FirstArgIn("-T", "-t"),
            "openssl" => !AnyArg("-out"),
            "auditctl" => AllArgsStartWith("-l", "-s", "-v"),
            "augenrules" => FirstArgIn("--check"),
            "semanage" => (args.Contains("-l") || args.Contains("--list"))
                          && !AnyArg("-a", "-d", "-m", "-D", "-i", "--add", "--delete", "--modify", "--deleteall", "--import"),
            "semodule" => AllArgsStartWith("-l", "--list-modules"),
            "faillock" => !AnyArg("--reset", "-r"),
            "chage" => FirstArgIn("-l", "--list"),
            "passwd" => FirstArgIn("-S", "--status"),
            "crontab" => FirstArgIn("-l"),
            "modprobe" => FirstArgIn("--showconfig", "-c", "--show-depends"),
            "mount" => args.Length == 0 || AllArgsStartWith("-l"),
            "ip" => !args.Any(a => a is "add" or "del" or "delete" or "set" or "change" or "replace" or "flush"),
            "iptables" or "ip6tables" => AnyArg("-L", "-S", "--list")
                                         && !AnyArg("-A", "-I", "-D", "-F", "-P", "-X", "-N", "-R", "-Z", "--append",
                                             "--insert", "--delete", "--flush", "--policy"),
            "nft" => FirstArgIn("list"),
            "timedatectl" or "hostnamectl" => args.Length == 0 || FirstArgIn("status", "show", "list-timezones"),
            "loginctl" => FirstArgIn("list-sessions", "list-users", "show-session", "show-user", "session-status", "user-status"),
            "postconf" => !AnyArg("-e", "-#", "-X", "--edit"),
            "cryptsetup" => FirstArgIn("status", "luksDump", "isLuks"),
            "pwck" or "grpck" => FirstArgIn("-r", "--read-only"),
            "aide" => FirstArgIn("--check", "-C"),
            "oscap" => FirstArgIn("info", "version"),
            "rsyslogd" => AllArgsStartWith("-N"),
            _ => false,
        };
    }

    /// <summary>
    /// <c>find</c> may run a command per match, and DISA uses that to list offenders: <c>-exec ls -l {} \;</c>.
    /// Only a command that is itself read-only is allowed there; <c>-delete</c> and file-writing actions never are.
    /// </summary>
    private static bool FindIsReadOnly(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "-delete" or "-fls" || args[i].StartsWith("-fprint", StringComparison.Ordinal)) return false;
            if (args[i] is not ("-exec" or "-execdir" or "-ok" or "-okdir")) continue;
            if (i + 1 >= args.Length) return false;
            var executed = args[i + 1][(args[i + 1].LastIndexOf('/') + 1)..];
            if (!AlwaysReadOnly.Contains(executed)) return false;
        }
        return true;
    }

    /// <summary>
    /// Reads the per-rule verdict oscap prints, e.g. "Result\tfail" or "Result: pass". oscap actually writes
    /// <c>Result\r\tpass</c> — a carriage return before the tab, to overwrite a progress line on a terminal — so the
    /// carriage return is dropped rather than treated as a line ending, which would put the verdict on its own line
    /// with no label and lose it.
    /// </summary>
    public static string? ParseOscapStatus(string output)
    {
        string[] statuses =
            ["pass", "fail", "notapplicable", "notchecked", "notselected", "error", "unknown", "fixed"];

        foreach (var line in (output ?? "").Replace("\r", "").Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith("Result", StringComparison.OrdinalIgnoreCase)) continue;

            var value = trimmed["Result".Length..].TrimStart(':', '\t', ' ').Trim().ToLowerInvariant();
            if (statuses.Contains(value)) return value;
        }

        return null;
    }
}
