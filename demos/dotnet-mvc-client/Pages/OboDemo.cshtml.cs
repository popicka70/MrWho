using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using MrWhoOidc.RazorClient.Services;

namespace MrWhoOidc.RazorClient.Pages;

[Authorize]
public class OboDemoModel : PageModel
{
    private readonly OboApiClient _oboApi;

    public OboDemoModel(OboApiClient oboApi) => _oboApi = oboApi;

    public OboApiClient.OboApiResponse? ApiResponse { get; private set; }
    public string? UserInfoJson { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnPostCallApiAsync()
    {
        try
        {
            ApiResponse = await _oboApi.GetIdentityAsync();
            if (ApiResponse is null)
                ErrorMessage = "API returned no response";

            if (ApiResponse?.UserInfo is not null)
            {
                UserInfoJson = JsonSerializer.Serialize(ApiResponse.UserInfo.Value, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        return Page();
    }
}
