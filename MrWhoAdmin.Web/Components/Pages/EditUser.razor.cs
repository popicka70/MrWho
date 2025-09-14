using Microsoft.AspNetCore.Components;
using MrWho.Shared.Models;
using MrWhoAdmin.Web.Services;
using Radzen;

namespace MrWhoAdmin.Web.Components.Pages;

public partial class EditUser
{
    [Parameter] public string? Id { get; set; }

    // Injected services
    [Inject] protected NavigationManager Navigation { get; set; } = default!;
    [Inject] protected NotificationService NotificationService { get; set; } = default!;
    [Inject] protected DialogService DialogService { get; set; } = default!;
    [Inject] protected IUsersApiService UsersApiService { get; set; } = default!;
    [Inject] protected ILogger<EditUser> Logger { get; set; } = default!;
    [Inject] protected IUserClientsApiService UserClientsApi { get; set; } = default!;
    [Inject] protected IClientsApiService ClientsApi { get; set; } = default!;
    [Inject] protected IClientUsersApiService ClientUsersApi { get; set; } = default!;

    internal bool IsEdit => !string.IsNullOrEmpty(Id);
    internal int selectedTabIndex = 0;

    // Loading states
    internal bool isLoading;
    internal bool isSaving;
    internal bool isDeleting;
    internal bool isAddingClaim;
    internal bool isAssigningRole;
    internal bool isTogglingLock;
    internal bool isResettingPassword;
    internal bool isForcingLogout;
    internal bool showPassword;

    // Data models
    internal UserWithClaimsDto? currentUser;
    internal UserEditModel userModel = new();
    internal string confirmPassword = string.Empty;
    internal List<UserClaimDto> userClaims = new();
    internal List<RoleDto> userRoles = new();
    internal List<RoleDto> availableRoles = new();

    // Claims
    internal string newClaimType = string.Empty;
    internal string newClaimValue = string.Empty;

    // Roles
    internal string selectedRoleId = string.Empty;

    // Clients
    internal List<UserClientDto> assignedClients = new();
    internal List<ClientDto> availableClients = new();
    internal string? selectedClientId;
    internal bool isAssigningClient;

    // Profile state
    internal UserProfileStateDto? profileState;

    // Aggregated data to share with child tabs
    internal List<ClientDto> aggregatedAllClients = new();
    internal List<ClientRoleDto> aggregatedAllClientRoles = new();
    internal Dictionary<string, List<string>> aggregatedUserClientRolesByClient = new();

    protected override async Task OnInitializedAsync()
    {
        if (IsEdit)
        {
            await LoadEditContext();
        }
        else
        {
            userModel.EmailConfirmed = false;
            userModel.PhoneNumberConfirmed = false;
            userModel.TwoFactorEnabled = false;
        }
    }

    private void ApplyContext(UserEditContextDto ctx)
    {
        currentUser = ctx.User!;
        userModel = new UserEditModel
        {
            UserName = currentUser.UserName,
            Email = currentUser.Email,
            PhoneNumber = currentUser.PhoneNumber,
            EmailConfirmed = currentUser.EmailConfirmed,
            PhoneNumberConfirmed = currentUser.PhoneNumberConfirmed,
            TwoFactorEnabled = currentUser.TwoFactorEnabled
        };
        userClaims = currentUser.Claims;
        userRoles = ctx.UserRoles;
        availableRoles = ctx.AvailableRoles;
        assignedClients = ctx.AssignedClients;
        availableClients = ctx.AvailableClients;
        profileState = ctx.ProfileState;
        aggregatedAllClients = ctx.AllClients;
        aggregatedAllClientRoles = ctx.AllClientRoles;
        aggregatedUserClientRolesByClient = ctx.UserClientRolesByClient;
    }

    private async Task LoadEditContext()
    {
        isLoading = true;
        try
        {
            var ctx = await UsersApiService.GetUserEditContextAsync(Id!);
            if (ctx?.User == null)
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "User not found");
                Navigation.NavigateTo("/users");
                return;
            }
            ApplyContext(ctx);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error loading edit context for user {UserId}", Id);
            NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to load user context");
        }
        finally
        {
            isLoading = false;
        }
    }

    private async Task LoadProfileState()
    {
        try { profileState = await UsersApiService.GetProfileStateAsync(Id!); }
        catch (Exception ex) { Logger.LogError(ex, "Error loading profile state for {UserId}", Id); }
    }

    internal async Task SetProfileState(string state)
    {
        var ok = await DialogService.Confirm($"Set profile state to '{state}'?", "Change Profile State", new ConfirmOptions() { OkButtonText = "Confirm", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        try
        {
            if (await UsersApiService.SetProfileStateAsync(Id!, new SetUserProfileStateRequest { State = state }))
            {
                NotificationService.Notify(NotificationSeverity.Success, "Updated", $"Profile state set to {state}");
                await LoadProfileState();
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to update profile state");
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error setting profile state for {UserId}", Id);
            NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to update profile state");
        }
    }

    private async Task LoadUserClients()
    {
        try { assignedClients = (await UserClientsApi.GetClientsForUserAsync(Id!))?.Clients ?? new(); }
        catch (Exception ex) { Logger.LogError(ex, "Error loading user clients {UserId}", Id); }
    }

    private async Task LoadAvailableClients()
    {
        try
        {
            var result = await ClientsApi.GetClientsAsync(page: 1, pageSize: 200);
            var all = result?.Items ?? new List<ClientDto>();
            availableClients = all.Where(c => !assignedClients.Any(ac => ac.ClientId == c.Id)).ToList();
        }
        catch (Exception ex) { Logger.LogError(ex, "Error loading available clients for user {UserId}", Id); }
    }

    internal async Task<bool> SetClientAssignment(string clientDbId, bool assign)
    {
        if (currentUser == null)
        {
            return false;
        }

        try
        {
            if (assign)
            {
                var res = await ClientUsersApi.AssignUserAsync(clientDbId, new AssignClientUserRequest { UserId = currentUser.Id, ClientId = clientDbId });
                if (res != null)
                {
                    NotificationService.Notify(NotificationSeverity.Success, "Assigned", $"Assigned to '{res.ClientName}'");
                    await LoadUserClients();
                    await LoadAvailableClients();
                    return true;
                }
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to assign client");
                return false;
            }
            else
            {
                var ok = await ClientUsersApi.RemoveUserAsync(clientDbId, currentUser.Id);
                if (ok)
                {
                    NotificationService.Notify(NotificationSeverity.Success, "Removed", "Client unassigned");
                    await LoadUserClients();
                    await LoadAvailableClients();
                    return true;
                }
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to remove client");
                return false;
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error changing client assignment for {UserId} client {ClientId}", Id, clientDbId);
            NotificationService.Notify(NotificationSeverity.Error, "Error", ex.Message);
            return false;
        }
    }

    internal async Task OnSaveUser()
    {
        if (string.IsNullOrWhiteSpace(userModel.Email)) { NotificationService.Notify(NotificationSeverity.Warning, "Validation", "Email required"); return; }
        if (!IsEdit)
        {
            if (string.IsNullOrWhiteSpace(userModel.Password)) { NotificationService.Notify(NotificationSeverity.Warning, "Validation", "Password required"); return; }
            if (userModel.Password != confirmPassword) { NotificationService.Notify(NotificationSeverity.Warning, "Validation", "Passwords do not match"); return; }
        }
        isSaving = true;
        try
        {
            if (string.IsNullOrWhiteSpace(userModel.UserName))
            {
                userModel.UserName = userModel.Email;
            }

            if (IsEdit)
            {
                var update = new UpdateUserRequest
                {
                    Email = userModel.Email,
                    UserName = userModel.UserName,
                    PhoneNumber = userModel.PhoneNumber,
                    EmailConfirmed = userModel.EmailConfirmed,
                    PhoneNumberConfirmed = userModel.PhoneNumberConfirmed,
                    TwoFactorEnabled = userModel.TwoFactorEnabled
                };
                var updated = await UsersApiService.UpdateUserAsync(Id!, update);
                NotificationService.Notify(updated != null ? NotificationSeverity.Success : NotificationSeverity.Error,
                    updated != null ? "Success" : "Error",
                    updated != null ? "User updated" : "Failed to update user");
            }
            else
            {
                var create = new CreateUserRequest
                {
                    UserName = userModel.UserName,
                    Email = userModel.Email,
                    Password = userModel.Password!,
                    PhoneNumber = userModel.PhoneNumber,
                    EmailConfirmed = userModel.EmailConfirmed,
                    PhoneNumberConfirmed = userModel.PhoneNumberConfirmed,
                    TwoFactorEnabled = userModel.TwoFactorEnabled
                };
                var created = await UsersApiService.CreateUserAsync(create);
                if (created != null)
                {
                    NotificationService.Notify(NotificationSeverity.Success, "Success", "User created");
                    Navigation.NavigateTo($"/users/edit/{created.Id}");
                }
                else
                {
                    NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to create user");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error saving user");
            NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to save user");
        }
        finally { isSaving = false; }
    }

    internal async Task AddClaim()
    {
        if (string.IsNullOrWhiteSpace(newClaimType) || string.IsNullOrWhiteSpace(newClaimValue))
        {
            return;
        }

        isAddingClaim = true;
        try
        {
            var req = new AddUserClaimRequest { ClaimType = newClaimType.Trim(), ClaimValue = newClaimValue.Trim() };
            if (await UsersApiService.AddUserClaimAsync(Id!, req))
            {
                userClaims.Add(new UserClaimDto { ClaimType = req.ClaimType, ClaimValue = req.ClaimValue });
                newClaimType = newClaimValue = string.Empty;
                NotificationService.Notify(NotificationSeverity.Success, "Success", "Claim added");
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to add claim");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error adding claim {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to add claim"); }
        finally { isAddingClaim = false; }
    }

    internal async Task RemoveClaim(UserClaimDto claim)
    {
        var ok = await DialogService.Confirm($"Remove claim '{claim.ClaimType}'?", "Remove Claim", new ConfirmOptions() { OkButtonText = "Remove", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        try
        {
            if (await UsersApiService.RemoveUserClaimAsync(Id!, new RemoveUserClaimRequest { ClaimType = claim.ClaimType, ClaimValue = claim.ClaimValue }))
            {
                userClaims.Remove(claim);
                NotificationService.Notify(NotificationSeverity.Success, "Success", "Claim removed");
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to remove claim");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error removing claim {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to remove claim"); }
    }

    internal async Task AssignRole()
    {
        if (string.IsNullOrWhiteSpace(selectedRoleId))
        {
            return;
        }

        isAssigningRole = true;
        try
        {
            // Ensure UserId is set in request to satisfy [Required] validation on the API model
            if (await UsersApiService.AssignUserRoleAsync(Id!, new AssignRoleRequest { UserId = Id!, RoleId = selectedRoleId }))
            {
                var role = availableRoles.FirstOrDefault(r => r.Id == selectedRoleId);
                if (role != null)
                {
                    userRoles.Add(role);
                    availableRoles.Remove(role);
                    selectedRoleId = string.Empty;
                    NotificationService.Notify(NotificationSeverity.Success, "Success", "Role assigned");
                }
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to assign role");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error assigning role {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to assign role"); }
        finally { isAssigningRole = false; }
    }

    internal async Task RemoveRole(string roleId)
    {
        var role = userRoles.FirstOrDefault(r => r.Id == roleId); if (role == null)
        {
            return;
        }

        var ok = await DialogService.Confirm($"Remove role '{role.Name}'?", "Remove Role", new ConfirmOptions() { OkButtonText = "Remove", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        try
        {
            if (await UsersApiService.RemoveUserRoleAsync(Id!, roleId))
            {
                userRoles.Remove(role); availableRoles.Add(role);
                NotificationService.Notify(NotificationSeverity.Success, "Success", "Role removed");
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to remove role");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error removing role {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to remove role"); }
    }

    internal async Task AssignClient()
    {
        if (string.IsNullOrWhiteSpace(selectedClientId) || currentUser == null)
        {
            return;
        }

        isAssigningClient = true;
        try
        {
            var res = await ClientUsersApi.AssignUserAsync(selectedClientId, new AssignClientUserRequest { UserId = currentUser.Id, ClientId = selectedClientId });
            if (res != null)
            {
                NotificationService.Notify(NotificationSeverity.Success, "Assigned", $"Assigned to '{res.ClientName}'");
                await LoadUserClients(); await LoadAvailableClients(); selectedClientId = null;
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to assign client");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error assigning client {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", ex.Message); }
        finally { isAssigningClient = false; }
    }

    internal async Task RemoveClient(UserClientDto c)
    {
        if (currentUser == null)
        {
            return;
        }

        try
        {
            if (await ClientUsersApi.RemoveUserAsync(c.ClientId, currentUser.Id))
            { NotificationService.Notify(NotificationSeverity.Success, "Removed", $"Removed from '{c.ClientName}'"); await LoadUserClients(); await LoadAvailableClients(); }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to remove client");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error removing client {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", ex.Message); }
    }

    internal bool IsUserLocked() => currentUser?.LockoutEnd.HasValue == true && currentUser.LockoutEnd > DateTimeOffset.UtcNow;

    internal async Task LockUser()
    {
        var ok = await DialogService.Confirm("Lock user account?", "Lock Account", new ConfirmOptions() { OkButtonText = "Lock", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        isTogglingLock = true;
        try
        {
            var end = DateTimeOffset.UtcNow.AddYears(100);
            if (await UsersApiService.SetLockoutAsync(Id!, end)) { if (currentUser != null) { currentUser.LockoutEnd = end; } NotificationService.Notify(NotificationSeverity.Success, "Success", "User locked"); }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to lock user");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error locking user {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to lock user"); }
        finally { isTogglingLock = false; }
    }

    internal async Task UnlockUser()
    {
        var ok = await DialogService.Confirm("Unlock user account?", "Unlock Account", new ConfirmOptions() { OkButtonText = "Unlock", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        isTogglingLock = true;
        try
        {
            if (await UsersApiService.SetLockoutAsync(Id!, null)) { if (currentUser != null) { currentUser.LockoutEnd = null; } NotificationService.Notify(NotificationSeverity.Success, "Success", "User unlocked"); }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to unlock user");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error unlocking user {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to unlock user"); }
        finally { isTogglingLock = false; }
    }

    internal async Task ResetPassword()
    {
        var ok = await DialogService.Confirm("Reset password and generate temporary one?", "Reset Password", new ConfirmOptions() { OkButtonText = "Reset", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        isResettingPassword = true;
        try
        {
            var newPwd = GenerateTemporaryPassword();
            if (await UsersApiService.ResetPasswordAsync(Id!, newPwd))
            { await DialogService.Alert($"Temporary password: {newPwd}\nProvide securely.", "Password Reset"); NotificationService.Notify(NotificationSeverity.Success, "Success", "Password reset"); }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to reset password");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error resetting password {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to reset password"); }
        finally { isResettingPassword = false; }
    }

    internal async Task ForceLogout()
    {
        var ok = await DialogService.Confirm("Force logout all sessions?", "Force Logout", new ConfirmOptions() { OkButtonText = "Force Logout", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        isForcingLogout = true;
        try
        {
            if (await UsersApiService.ForceLogoutAsync(Id!))
            {
                NotificationService.Notify(NotificationSeverity.Success, "Success", "Sessions terminated");
            }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to force logout");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error forcing logout {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to force logout"); }
        finally { isForcingLogout = false; }
    }

    internal async Task DeleteUser()
    {
        var ok = await DialogService.Confirm($"Delete user '{currentUser?.UserName}'?", "Delete User", new ConfirmOptions() { OkButtonText = "Delete", CancelButtonText = "Cancel" });
        if (ok != true)
        {
            return;
        }

        isDeleting = true;
        try
        {
            if (await UsersApiService.DeleteUserAsync(Id!)) { NotificationService.Notify(NotificationSeverity.Success, "Success", "User deleted"); Navigation.NavigateTo("/users"); }
            else
            {
                NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to delete user");
            }
        }
        catch (Exception ex) { Logger.LogError(ex, "Error deleting user {UserId}", Id); NotificationService.Notify(NotificationSeverity.Error, "Error", "Failed to delete user"); }
        finally { isDeleting = false; }
    }

    internal void Cancel() => Navigation.NavigateTo("/users");

    internal void GeneratePassword()
    {
        var rnd = new Random();
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        userModel.Password = new string(Enumerable.Repeat(chars, 16).Select(s => s[rnd.Next(s.Length)]).ToArray());
        confirmPassword = userModel.Password;
        NotificationService.Notify(NotificationSeverity.Info, "Generated", "Password generated");
    }

    private string GenerateTemporaryPassword()
    {
        var rnd = new Random();
        const string chars = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        return new string(Enumerable.Repeat(chars, 12).Select(s => s[rnd.Next(s.Length)]).ToArray());
    }

    public class UserEditModel
    {
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? PhoneNumber { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
    }
}
