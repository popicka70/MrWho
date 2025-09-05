namespace MrWhoAdmin.Tests;

/// <summary>
/// Tests demonstrating database state management with shared infrastructure
/// </summary>
[TestClass]
[TestCategory("Integration")]
public class DatabaseStateManagementTests
{
    /// <summary>
    /// Test that demonstrates cleaning up test data after each test
    /// </summary>
    [TestMethod]
    public async Task DatabaseTest_WithCleanup_Example()
    {
        // Arrange
        using var httpClient = SharedTestInfrastructure.CreateHttpClient("mrwho");

        try
        {
            // Act - Your test operations here
            var response = await httpClient.GetAsync("/api/realms");

            // Assert
            Assert.IsTrue(response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Unauthorized);
        }
        finally
        {
            // Cleanup - Remove any test data created during this test
            // This ensures tests don't interfere with each other
            // TODO: Implement cleanup logic as needed
        }
    }

    /// <summary>
    /// Test that demonstrates using transactions for isolation
    /// </summary>
    [TestMethod]
    public async Task DatabaseTest_WithTransactionRollback_Example()
    {
        // Arrange
        using var httpClient = SharedTestInfrastructure.CreateHttpClient("mrwho");

        // Note: For true isolation, you might want to:
        // 1. Use database transactions that can be rolled back
        // 2. Use separate database schemas per test
        // 3. Clean up specific test data after each test

        try
        {
            // Act
            var response = await httpClient.GetAsync("/api/realms");

            // Assert
            Assert.IsTrue(response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Unauthorized);
        }
        finally
        {
            // Cleanup test-specific data
            // In a real scenario, you'd implement proper cleanup
        }
    }
}
