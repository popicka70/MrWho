using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using MrWhoOidc.RazorClient.Services;

namespace MrWhoOidc.RazorClient.Pages;

/// <summary>
/// Demonstrates the difference between OBO (on-behalf-of user) and M2M (machine-to-machine) token flows
/// by calling the same API endpoint with tokens acquired via different OAuth grant types.
/// </summary>
[Authorize]
public class TokenComparisonModel : PageModel
{
    private readonly OboApiClient _oboApi;
    private readonly M2MApiClient _m2mApi;

    public TokenComparisonModel(OboApiClient oboApi, M2MApiClient m2mApi)
    {
        _oboApi = oboApi;
        _m2mApi = m2mApi;
    }

    public OboApiClient.OboApiResponse? OboResponse { get; private set; }
    public M2MApiClient.M2MApiResponse? M2MResponse { get; private set; }
    public string? OboJson { get; private set; }
    public string? M2MJson { get; private set; }
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Handler for calling both APIs in parallel.
    /// </summary>
    public async Task<IActionResult> OnPostCallBothAsync()
    {
        try
        {
            // Call both APIs in parallel for comparison
            var oboTask = _oboApi.GetIdentityAsync();
            var m2mTask = _m2mApi.GetIdentityAsync();
            
            await Task.WhenAll(oboTask, m2mTask);
            
            OboResponse = oboTask.Result;
            M2MResponse = m2mTask.Result;
            
            SerializeResponses();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
        return Page();
    }

    /// <summary>
    /// Handler for calling only the OBO API.
    /// </summary>
    public async Task<IActionResult> OnPostCallOboAsync()
    {
        try
        {
            OboResponse = await _oboApi.GetIdentityAsync();
            SerializeOboResponse();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"OBO Error: {ex.Message}";
        }
        return Page();
    }

    /// <summary>
    /// Handler for calling only the M2M API.
    /// </summary>
    public async Task<IActionResult> OnPostCallM2MAsync()
    {
        try
        {
            M2MResponse = await _m2mApi.GetIdentityAsync();
            SerializeM2MResponse();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"M2M Error: {ex.Message}";
        }
        return Page();
    }

    private void SerializeResponses()
    {
        SerializeOboResponse();
        SerializeM2MResponse();
    }

    private void SerializeOboResponse()
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        OboJson = OboResponse is not null 
            ? JsonSerializer.Serialize(OboResponse, jsonOptions) 
            : null;
    }

    private void SerializeM2MResponse()
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        M2MJson = M2MResponse is not null 
            ? JsonSerializer.Serialize(M2MResponse, jsonOptions) 
            : null;
    }
}
