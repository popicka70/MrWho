using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MrWhoOidc.RazorClient.Services;

namespace MrWhoOidc.RazorClient.Pages;

[Authorize]
public class OboDemoModel : PageModel
{
    private readonly OboApiClient _oboApi;

    public OboDemoModel(OboApiClient oboApi) => _oboApi = oboApi;

    public OboApiClient.OboApiResponse? ApiResponse { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnPostCallApiAsync()
    {
        try
        {
            ApiResponse = await _oboApi.GetProfileAsync();
            if (ApiResponse is null)
                ErrorMessage = "API returned no response";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        return Page();
    }
}
