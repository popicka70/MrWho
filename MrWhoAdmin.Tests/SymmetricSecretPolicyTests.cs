using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MrWho.Options;
using MrWho.Services;
using System.Text;

namespace MrWhoAdmin.Tests;

[TestClass]
public class SymmetricSecretPolicyTests
{
    private readonly ISymmetricSecretPolicy _policy = new SymmetricSecretPolicy(
        Options.Create(new SymmetricSecretPolicyOptions()),
        NullLogger<SymmetricSecretPolicy>.Instance);

    private static string MakeSecret(int bytes)
    {
        // produce deterministic ASCII secret of requested length
        return new string('A', bytes);
    }

    [TestMethod]
    [DataRow("HS256", 31, false)]
    [DataRow("HS256", 32, true)]
    [DataRow("HS384", 47, false)]
    [DataRow("HS384", 48, true)]
    [DataRow("HS512", 48, false)] // explicit acceptance test requirement
    [DataRow("HS512", 63, false)]
    [DataRow("HS512", 64, true)]
    public void Boundary_Lengths_Enforced(string alg, int length, bool expectedPass)
    {
        var secret = MakeSecret(length);
        var res = _policy.ValidateForAlgorithm(alg, secret);
        Assert.AreEqual(expectedPass, res.Success, $"Expected {(expectedPass ? "pass" : "fail")} for {alg} length {length} (required {res.RequiredBytes})");
    }

    [TestMethod]
    public void Downgrade_Attempt_Fails_When_New_Secret_Too_Short_For_Previously_Allowed_Alg()
    {
        // Simulate existing client previously satisfying HS512 (64 bytes)
        var original = MakeSecret(64);
        var ok = _policy.ValidateForAlgorithm("HS512", original);
        Assert.IsTrue(ok.Success, "64 byte secret should satisfy HS512");

        // Rotation/downgrade to 48 bytes while still intending HS512
        var downgraded = MakeSecret(48);
        var fail = _policy.ValidateForAlgorithm("HS512", downgraded);
        Assert.IsFalse(fail.Success, "HS512 must be rejected with 48 byte secret (downgrade attempt)");
    }

    [TestMethod]
    public void Non_HS_Alg_Passes_Unchecked()
    {
        var res = _policy.ValidateForAlgorithm("RS256", MakeSecret(1));
        Assert.IsTrue(res.Success);
    }
}
