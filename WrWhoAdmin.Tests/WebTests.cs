using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using MrWho.Controllers;
using MrWho.Data;
using MrWho.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using MrWho.Handlers.Users;
using MrWhoAdmin.Web.Extensions;

namespace MrWhoAdmin.Tests;

/// <summary>
/// Integration tests for the web application
/// </summary>
[TestClass]
public class WebTests
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    [TestMethod]
    public async Task GetWebResourceRootReturnsOkStatusCode()
    {
        // Arrange
        var cancellationToken = new CancellationTokenSource(DefaultTimeout).Token;

        var appHost = await DistributedApplicationTestingBuilder.CreateAsync<Projects.MrWhoAdmin_AppHost>(cancellationToken);
        appHost.Services.AddLogging(logging =>
        {
            logging.SetMinimumLevel(LogLevel.Debug);
            // Override the logging filters from the app's configuration
            logging.AddFilter(appHost.Environment.ApplicationName, LogLevel.Debug);
            logging.AddFilter("Aspire.", LogLevel.Debug);
        });
        appHost.Services.ConfigureHttpClientDefaults(clientBuilder =>
        {
            clientBuilder.AddStandardResilienceHandler();
        });

        await using var app = await appHost.BuildAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        await app.StartAsync(cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);

        // Act
        var httpClient = app.CreateHttpClient("webfrontend");
        await app.ResourceNotifications.WaitForResourceHealthyAsync("webfrontend", cancellationToken).WaitAsync(DefaultTimeout, cancellationToken);
        var response = await httpClient.GetAsync("/", cancellationToken);

        // Assert
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }
}

/// <summary>
/// Tests for the RealmsController using MrWho.Models
/// </summary>
[TestClass]
public class RealmsControllerTests
{
    private ApplicationDbContext _context = null!;
    private RealmsController _controller = null!;
    private Mock<ILogger<RealmsController>> _mockLogger = null!;

    [TestInitialize]
    public void Setup()
    {
        // Create in-memory database
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        // Create mock logger
        _mockLogger = new Mock<ILogger<RealmsController>>();

        // Create controller
        _controller = new RealmsController(_context, _mockLogger.Object);

        // Set up HTTP context with user identity
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "test-user")
        }, "test"));

        _controller.ControllerContext = new ControllerContext()
        {
            HttpContext = new DefaultHttpContext() { User = user }
        };
    }

    [TestCleanup]
    public void Cleanup()
    {
        _context.Dispose();
    }

    [TestMethod]
    public async Task GetRealms_WithNoRealms_ReturnsEmptyPagedResult()
    {
        // Act
        var result = await _controller.GetRealms();

        // Assert
        result.Should().NotBeNull();
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var pagedResult = okResult.Value.Should().BeOfType<MrWho.Models.PagedResult<MrWho.Models.RealmDto>>().Subject;
        pagedResult.Items.Should().BeEmpty();
        pagedResult.TotalCount.Should().Be(0);
        pagedResult.Page.Should().Be(1);
        pagedResult.PageSize.Should().Be(10);
        pagedResult.TotalPages.Should().Be(0);
    }

    [TestMethod]
    public async Task GetRealms_WithRealms_ReturnsPagedResult()
    {
        // Arrange
        await SeedTestRealms();

        // Act
        var result = await _controller.GetRealms();

        // Assert
        result.Should().NotBeNull();
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var pagedResult = okResult.Value.Should().BeOfType<MrWho.Models.PagedResult<MrWho.Models.RealmDto>>().Subject;
        pagedResult.Items.Should().HaveCount(2);
        pagedResult.TotalCount.Should().Be(2);
        pagedResult.Page.Should().Be(1);
        pagedResult.PageSize.Should().Be(10);
        pagedResult.TotalPages.Should().Be(1);
    }

    [TestMethod]
    public async Task CreateRealm_WithValidRequest_CreatesRealm()
    {
        // Arrange
        var request = new MrWho.Models.CreateRealmRequest
        {
            Name = "New Realm",
            DisplayName = "New Realm Display",
            Description = "A new test realm",
            IsEnabled = true,
            AccessTokenLifetime = TimeSpan.FromMinutes(60),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(10)
        };

        // Act
        var result = await _controller.CreateRealm(request);

        // Assert
        result.Should().NotBeNull();
        var createdResult = result.Result.Should().BeOfType<CreatedAtActionResult>().Subject;
        var realmDto = createdResult.Value.Should().BeOfType<MrWho.Models.RealmDto>().Subject;
        realmDto.Name.Should().Be("New Realm");
        realmDto.IsEnabled.Should().BeTrue();

        // Verify realm was saved to database
        var savedRealm = await _context.Realms.FindAsync(realmDto.Id);
        savedRealm.Should().NotBeNull();
        savedRealm!.Name.Should().Be("New Realm");
    }

    [TestMethod]
    public async Task CreateRealm_WithDuplicateName_ReturnsBadRequest()
    {
        // Arrange
        await SeedTestRealms();
        var request = new MrWho.Models.CreateRealmRequest
        {
            Name = "Test Realm", // This name already exists
            DisplayName = "Duplicate Realm",
            Description = "A duplicate realm",
            IsEnabled = true
        };

        // Act
        var result = await _controller.CreateRealm(request);

        // Assert
        result.Should().NotBeNull();
        result.Result.Should().BeOfType<BadRequestObjectResult>();
    }

    private async Task SeedTestRealms()
    {
        var testRealm = new Realm
        {
            Id = Guid.NewGuid().ToString(),
            Name = "Test Realm",
            DisplayName = "Test Realm Display",
            Description = "A test realm for unit tests",
            IsEnabled = true,
            AccessTokenLifetime = TimeSpan.FromMinutes(60),
            RefreshTokenLifetime = TimeSpan.FromDays(30),
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(10),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            CreatedBy = "test-user",
            UpdatedBy = "test-user"
        };

        var anotherRealm = new Realm
        {
            Id = Guid.NewGuid().ToString(),
            Name = "Another Realm",
            DisplayName = "Another Test Realm",
            Description = "Another test realm",
            IsEnabled = false,
            AccessTokenLifetime = TimeSpan.FromMinutes(30),
            RefreshTokenLifetime = TimeSpan.FromDays(7),
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(5),
            CreatedAt = DateTime.UtcNow.AddDays(-1),
            UpdatedAt = DateTime.UtcNow.AddDays(-1),
            CreatedBy = "test-user",
            UpdatedBy = "test-user"
        };

        _context.Realms.AddRange(testRealm, anotherRealm);
        await _context.SaveChangesAsync();
    }
}

/// <summary>
/// Tests for Service Extensions
/// </summary>
[TestClass]
public class ServiceExtensionTests
{
    [TestMethod]
    public void AddHttpServices_RegistersRequiredServices()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        services.AddHttpServices();

        // Assert
        services.Should().Contain(s => s.ServiceType == typeof(IHttpContextAccessor));
    }

    [TestMethod]
    public void AddAuthorizationServices_DoesNotThrow()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act & Assert - Should not throw
        var result = services.AddAuthorizationServices();
        result.Should().NotBeNull();
    }
}

/// <summary>
/// Tests for User Handlers
/// </summary>
[TestClass]
public class UserHandlerTests
{
    [TestMethod]
    public void GetUsersHandler_WithInvalidPageParameters_ClampsToValidValues()
    {
        // Arrange
        var mockUserStore = new Mock<IUserStore<IdentityUser>>();
        var mockUserManagerLogger = new Mock<ILogger<UserManager<IdentityUser>>>();
        var mockPasswordHasher = new Mock<IPasswordHasher<IdentityUser>>();
        var mockKeyNormalizer = new Mock<ILookupNormalizer>();
        var mockErrorDescriber = new Mock<IdentityErrorDescriber>();
        var mockServiceProvider = new Mock<IServiceProvider>();

        var userManager = new UserManager<IdentityUser>(
            mockUserStore.Object,
            null, // IOptions<IdentityOptions>
            mockPasswordHasher.Object,
            null, // IEnumerable<IUserValidator<IdentityUser>>
            null, // IEnumerable<IPasswordValidator<IdentityUser>>
            mockKeyNormalizer.Object,
            mockErrorDescriber.Object,
            mockServiceProvider.Object,
            mockUserManagerLogger.Object);

        mockUserStore.As<IQueryableUserStore<IdentityUser>>()
            .Setup(x => x.Users)
            .Returns(new List<IdentityUser>().AsQueryable());

        var handler = new GetUsersHandler(userManager);

        // Act & Assert - Test negative page
        var result1 = handler.HandleAsync(-1, 10, null).Result;
        result1.Page.Should().Be(1);

        // Act & Assert - Test zero page
        var result2 = handler.HandleAsync(0, 10, null).Result;
        result2.Page.Should().Be(1);

        // Act & Assert - Test invalid page size
        var result3 = handler.HandleAsync(1, 0, null).Result;
        result3.PageSize.Should().Be(10);

        // Act & Assert - Test too large page size
        var result4 = handler.HandleAsync(1, 200, null).Result;
        result4.PageSize.Should().Be(10);
    }
}

/// <summary>
/// Tests for model validation and behavior
/// </summary>
[TestClass]
public class ModelTests
{
    [TestMethod]
    public void MrWhoPagedResult_WithValidData_CalculatesCorrectProperties()
    {
        // Act
        var result = new MrWho.Models.PagedResult<string>
        {
            Items = new List<string> { "item1", "item2" },
            TotalCount = 25,
            Page = 3,
            PageSize = 10,
            TotalPages = (int)Math.Ceiling(25.0 / 10.0)
        };

        // Assert
        result.TotalPages.Should().Be(3);
        result.Items.Should().HaveCount(2);
        result.TotalCount.Should().Be(25);
        result.Page.Should().Be(3);
        result.PageSize.Should().Be(10);
    }

    [TestMethod]
    public void MrWhoRealmDto_DefaultValues_AreCorrect()
    {
        // Act
        var realm = new MrWho.Models.RealmDto();

        // Assert
        realm.Id.Should().Be(string.Empty);
        realm.Name.Should().Be(string.Empty);
        realm.IsEnabled.Should().BeTrue();
        realm.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(60));
        realm.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(30));
        realm.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromMinutes(10));
        realm.ClientCount.Should().Be(0);
    }

    [TestMethod]
    public void MrWhoCreateRealmRequest_DefaultValues_AreCorrect()
    {
        // Act
        var request = new MrWho.Models.CreateRealmRequest();

        // Assert
        request.Name.Should().Be(string.Empty);
        request.IsEnabled.Should().BeTrue();
        request.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(60));
        request.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(30));
        request.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromMinutes(10));
    }

    [TestMethod]
    public void MrWhoClientDto_DefaultValues_AreCorrect()
    {
        // Act
        var client = new MrWho.Models.ClientDto();

        // Assert
        client.Id.Should().Be(string.Empty);
        client.ClientId.Should().Be(string.Empty);
        client.Name.Should().Be(string.Empty);
        client.IsEnabled.Should().BeFalse();
        client.ClientType.Should().Be(MrWho.Models.ClientType.Confidential);
        client.RedirectUris.Should().NotBeNull();
        client.PostLogoutUris.Should().NotBeNull();
        client.Scopes.Should().NotBeNull();
        client.Permissions.Should().NotBeNull();
    }

    [TestMethod]
    public void MrWhoCreateClientRequest_DefaultValues_AreSecure()
    {
        // Act
        var request = new MrWho.Models.CreateClientRequest();

        // Assert - Verify secure defaults
        request.IsEnabled.Should().BeTrue();
        request.ClientType.Should().Be(MrWho.Models.ClientType.Confidential);
        request.AllowAuthorizationCodeFlow.Should().BeTrue();
        request.AllowClientCredentialsFlow.Should().BeFalse();
        request.AllowPasswordFlow.Should().BeFalse();
        request.AllowRefreshTokenFlow.Should().BeTrue();
        request.RequirePkce.Should().BeTrue();
        request.RequireClientSecret.Should().BeTrue();
    }
}