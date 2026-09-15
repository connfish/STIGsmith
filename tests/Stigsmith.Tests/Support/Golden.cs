namespace Stigsmith.Tests.Support;

/// <summary>
/// Golden-file comparison. Set <c>STIGSMITH_UPDATE_GOLDEN=1</c> to rewrite the goldens from current
/// behaviour; the diff is then reviewed like any other change. Without it, a mismatch fails.
/// </summary>
public static class Golden
{
    private static bool Updating =>
        Environment.GetEnvironmentVariable("STIGSMITH_UPDATE_GOLDEN") is "1" or "true";

    public static void Assert(string actual, params string[] goldenPathParts)
    {
        var path = TestEnvironment.FixturePath([.. new[] { "golden" }.Concat(goldenPathParts)]);

        if (Updating || !File.Exists(path))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, actual);
            if (!Updating)
                throw new InvalidOperationException(
                    $"Golden file did not exist and has been created at {path}. Review it and re-run.");
            return;
        }

        var expected = File.ReadAllText(path);
        if (Normalize(actual) == Normalize(expected)) return;

        throw new ShouldAssertException(
            $"Output does not match golden file {Path.GetFileName(path)}.\n" +
            $"First difference at offset {FirstDifference(Normalize(expected), Normalize(actual))}.\n" +
            "Re-run with STIGSMITH_UPDATE_GOLDEN=1 and review the diff if the change is intended.");
    }

    private static string Normalize(string s) => s.Replace("\r\n", "\n");

    private static int FirstDifference(string a, string b)
    {
        var n = Math.Min(a.Length, b.Length);
        for (var i = 0; i < n; i++)
            if (a[i] != b[i]) return i;
        return n;
    }
}
