using System.ComponentModel.DataAnnotations;

namespace MrWho.Shared.Models;

/// <summary>
/// Request to add a claim to a user
/// </summary>
public class AddUserClaimRequest
{
    [Required]
    [StringLength(256)]
    public string ClaimType { get; set; } = string.Empty;

    [Required]
    [StringLength(1000)]
    public string ClaimValue { get; set; } = string.Empty;
}

/// <summary>
/// Request to remove a claim from a user
/// </summary>
public class RemoveUserClaimRequest
{
    [Required]
    [StringLength(256)]
    public string ClaimType { get; set; } = string.Empty;

    [Required]
    [StringLength(1000)]
    public string ClaimValue { get; set; } = string.Empty;
}

/// <summary>
/// User with claims DTO (extended user information)
/// </summary>
public class UserWithClaimsDto : UserDto
{
    public List<UserClaimDto> Claims { get; set; } = new();
    public List<string> Roles { get; set; } = new();
}

/// <summary>
/// Claim type information for UI dropdown
/// </summary>
public class ClaimTypeInfo
{
    public string Type { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public ClaimTypeInfo() { }

    public ClaimTypeInfo(string type, string displayName, string description)
    {
        Type = type;
        DisplayName = displayName;
        Description = description;
    }
}

/// <summary>
/// Predefined claim types for UI helpers
/// </summary>
public static class CommonClaimTypes
{
    public static readonly List<ClaimTypeInfo> StandardClaims = new()
    {
        new("given_name", "Given Name", "First name of the user"),
        new("family_name", "Family Name", "Last name of the user"),
        new("middle_name", "Middle Name", "Middle name of the user"),
        new("nickname", "Nickname", "Casual name of the user"),
        new("profile", "Profile URL", "URL of the user's profile page"),
        new("picture", "Picture URL", "URL of the user's profile picture"),
        new("website", "Website", "URL of the user's website or blog"),
        new("gender", "Gender", "User's gender"),
        new("birthdate", "Birth Date", "User's birthday (YYYY-MM-DD format)"),
        new("zoneinfo", "Time Zone", "String from zoneinfo time zone database"),
        new("locale", "Locale", "User's locale (e.g., en-US)"),
        new("updated_at", "Updated At", "Time the user's information was last updated"),
        
        // Custom business claims
        new("department", "Department", "User's department or division"),
        new("job_title", "Job Title", "User's job title or position"),
        new("employee_id", "Employee ID", "Unique employee identifier"),
        new("manager_email", "Manager Email", "Email of the user's manager"),
        new("office_location", "Office Location", "Physical office location"),
        new("cost_center", "Cost Center", "Accounting cost center"),
        new("hire_date", "Hire Date", "Date the user was hired"),
        new("contract_type", "Contract Type", "Type of employment contract"),
        
        // System claims
        new("preferred_language", "Preferred Language", "User's preferred interface language"),
        new("timezone", "Timezone", "User's preferred timezone"),
        new("theme", "Theme", "User's UI theme preference")
    };
}