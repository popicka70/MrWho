using System.Net.Http.Json;
using System.Text.Json;
using MrWho.Web.Models;

namespace MrWho.Web.Services;

public interface IUserApiClient
{
    Task<UserRegistrationResponse?> CreateUserAsync(UserRegistrationModel model);
    Task<UserRegistrationResponse?> GetUserAsync(string id);
    Task<IEnumerable<UserRegistrationResponse>> GetUsersAsync(int skip = 0, int take = 50);
    Task<bool> DeleteUserAsync(string id);
}

public class UserApiClient : IUserApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<UserApiClient> _logger;

    public UserApiClient(HttpClient httpClient, ILogger<UserApiClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<UserRegistrationResponse?> CreateUserAsync(UserRegistrationModel model)
    {
        try
        {
            var createRequest = new
            {
                email = model.Email,
                password = model.Password,
                firstName = model.FirstName,
                lastName = model.LastName,
                userName = model.UserName ?? model.Email
            };

            _logger.LogInformation("Attempting to create user with email: {Email}", model.Email);
            
            var response = await _httpClient.PostAsJsonAsync("/api/users", createRequest);
            
            if (response.IsSuccessStatusCode)
            {
                var user = await response.Content.ReadFromJsonAsync<UserRegistrationResponse>();
                _logger.LogInformation("User created successfully with ID: {UserId}", user?.Id);
                return user;
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Failed to create user. Status: {StatusCode}, Content: {Content}", 
                    response.StatusCode, errorContent);
                
                // Try to parse API error response
                if (!string.IsNullOrEmpty(errorContent))
                {
                    try
                    {
                        var apiError = JsonSerializer.Deserialize<ApiErrorResponse>(errorContent, 
                            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        
                        if (apiError?.Errors != null)
                        {
                            var errorMessages = apiError.Errors.SelectMany(e => e.Value);
                            _logger.LogError("API validation errors: {Errors}", string.Join(", ", errorMessages));
                        }
                    }
                    catch (JsonException)
                    {
                        // If we can't parse the error, just log the raw content
                        _logger.LogError("Raw error response: {ErrorContent}", errorContent);
                    }
                }
                
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while creating user");
            return null;
        }
    }

    public async Task<UserRegistrationResponse?> GetUserAsync(string id)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/api/users/{id}");
            
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<UserRegistrationResponse>();
            }
            
            _logger.LogWarning("Failed to get user {UserId}. Status: {StatusCode}", id, response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while getting user {UserId}", id);
            return null;
        }
    }

    public async Task<IEnumerable<UserRegistrationResponse>> GetUsersAsync(int skip = 0, int take = 50)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/api/users?skip={skip}&take={take}");
            
            if (response.IsSuccessStatusCode)
            {
                var users = await response.Content.ReadFromJsonAsync<IEnumerable<UserRegistrationResponse>>();
                return users ?? Enumerable.Empty<UserRegistrationResponse>();
            }
            
            _logger.LogWarning("Failed to get users. Status: {StatusCode}", response.StatusCode);
            return Enumerable.Empty<UserRegistrationResponse>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while getting users");
            return Enumerable.Empty<UserRegistrationResponse>();
        }
    }

    public async Task<bool> DeleteUserAsync(string id)
    {
        try
        {
            var response = await _httpClient.DeleteAsync($"/api/users/{id}");
            
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("User {UserId} deleted successfully", id);
                return true;
            }
            
            _logger.LogWarning("Failed to delete user {UserId}. Status: {StatusCode}", id, response.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception occurred while deleting user {UserId}", id);
            return false;
        }
    }
}