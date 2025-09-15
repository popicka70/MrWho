using System.Text.RegularExpressions;

namespace MrWhoAdmin.Tests;

[TestClass]
[TestCategory("OIDC")] 
public class ErrorCatalogSnapshotTests
{
    private static readonly string[] ExpectedReasons = new[]
    {
        "empty request object",
        "request object too large",
        "request object must be JWT",
        "missing alg",
        "client_id mismatch",
        "client_id missing",
        "unknown client",
        "alg not allowed",
        "alg not supported",
        "exp invalid",
        "iat invalid",
        "nbf in future",
        "jti required",
        "jti replay",
        "client secret missing",
        "client secret length below policy",
        "signature invalid",
        "invalid client JAR public key",
        "iss invalid",
        "aud invalid",
        "conflict parameter mismatch",
        "claim count limit",
        "claim value too long",
        "invalid request object",
        "request object required for this client",
        "invalid_request_uri_reuse_policy"
    };

    [TestMethod]
    public void ErrorCatalog_Document_Reasons_Match_Snapshot()
    {
        var solutionRoot = GetSolutionRoot();
        var docPath = Path.Combine(solutionRoot, "docs", "error-catalog-jar-par.md");
        Assert.IsTrue(File.Exists(docPath), $"Catalog file missing: {docPath}");
        var lines = File.ReadAllLines(docPath);

        var reasons = new HashSet<string>(StringComparer.Ordinal);
        var delimiterRegex = new Regex(@"^\|\s*-+\s*\|");
        foreach (var line in lines)
        {
            if (!line.StartsWith("|")) continue;
            if (delimiterRegex.IsMatch(line)) continue;
            var cols = line.Split('|');
            if (cols.Length < 3) continue;
            var firstCol = cols[1].Trim();
            if (string.Equals(firstCol, "Internal Reason", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.IsNullOrWhiteSpace(firstCol)) continue;
            reasons.Add(firstCol);
        }

        var missing = ExpectedReasons.Where(r => !reasons.Contains(r)).ToList();
        if (missing.Count > 0)
        {
            Assert.Fail($"Error catalog drift detected. Missing:[{string.Join(",", missing)}]");
        }

        // Optionally log extras (not failing build) for informational purposes
        var extra = reasons.Where(r => !ExpectedReasons.Contains(r, StringComparer.Ordinal)).ToList();
        if (extra.Count > 0)
        {
            Console.WriteLine($"[INFO] Extra reasons present (ignored): {string.Join(",", extra)}");
        }
    }

    private static string GetSolutionRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8; i++)
        {
            if (File.Exists(Path.Combine(dir, "docs", "error-catalog-jar-par.md"))) return dir;
            var parent = Directory.GetParent(dir); if (parent == null) break; dir = parent.FullName;
        }
        return AppContext.BaseDirectory;
    }
}
