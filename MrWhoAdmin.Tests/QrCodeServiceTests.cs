using MrWho.Services;

namespace MrWhoAdmin.Tests;

[TestClass]
public class QrCodeServiceTests
{
    [TestMethod]
    public void GeneratePngDataUri_Returns_DataUri()
    {
        var svc = new QrCodeService();
        var dataUri = svc.GeneratePngDataUri("hello world");
        StringAssert.StartsWith(dataUri, "data:image/png;base64,");
    }

    [TestMethod]
    public void GeneratePngDataUri_Throws_On_Empty()
    {
        var svc = new QrCodeService();
        Assert.ThrowsExactly<ArgumentException>(() => svc.GeneratePngDataUri(""));
    }
}
