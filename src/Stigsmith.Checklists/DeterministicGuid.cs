using System.Security.Cryptography;
using System.Text;

namespace Stigsmith.Checklists;

/// <summary>
/// Name-based UUIDs, so exporting the same checklist twice produces the same document.
/// </summary>
/// <remarks>
/// The .cklb format carries a <c>uuid</c> on the checklist, on each benchmark, and on each rule.
/// When Stigsmith synthesizes a .cklb from a source that has none (a .ckl, or XCCDF results), those
/// ids have to come from somewhere. Generating them randomly would mean two exports of an unchanged
/// checklist differ in every rule, which makes diffing exports useless and re-import churn the
/// database. Deriving them from the rule's own identity fixes that: same input, same ids, forever.
/// <para>
/// This is an RFC 9562 version 8 UUID (custom, SHA-256 based) rather than a version 5, because
/// version 5 mandates SHA-1 and there is no reason to reach for SHA-1 in new code. Nothing here is
/// a security boundary — these are content-addressed labels.
/// </para>
/// </remarks>
public static class DeterministicGuid
{
    /// <summary>Namespace prefix, so ids minted here cannot collide with another tool's v8 UUIDs.</summary>
    private const string Namespace = "urn:stigsmith:cklb:";

    /// <summary>
    /// The unit separator cannot appear in a rule id, a STIG id, or a hostname, so no two different
    /// part lists can hash to the same input string.
    /// </summary>
    private const char PartSeparator = '';

    public static Guid From(params ReadOnlySpan<string> parts)
    {
        var name = Namespace + string.Join(PartSeparator, parts.ToArray());
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(name));

        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(bytes);

        // Version 8 (custom) and the RFC 4122 variant, per RFC 9562 section 5.8.
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);

        return new Guid(bytes, bigEndian: true);
    }

    public static string String(params ReadOnlySpan<string> parts) => From(parts).ToString();
}
