using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MrWho.Models;
using MrWho.Handlers.Users;

namespace MrWho.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly IGetUsersHandler _getUsersHandler;
    private readonly IGetUserHandler _getUserHandler;
    private readonly ICreateUserHandler _createUserHandler;
    private readonly IUpdateUserHandler _updateUserHandler;
    private readonly IDeleteUserHandler _deleteUserHandler;
    private readonly IChangePasswordHandler _changePasswordHandler;
    private readonly IResetPasswordHandler _resetPasswordHandler;
    private readonly ISetLockoutHandler _setLockoutHandler;
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        IGetUsersHandler getUsersHandler,
        IGetUserHandler getUserHandler,
        ICreateUserHandler createUserHandler,
        IUpdateUserHandler updateUserHandler,
        IDeleteUserHandler deleteUserHandler,
        IChangePasswordHandler changePasswordHandler,
        IResetPasswordHandler resetPasswordHandler,
        ISetLockoutHandler setLockoutHandler,
        ILogger<UsersController> logger)
    {
        _getUsersHandler = getUsersHandler;
        _getUserHandler = getUserHandler;
        _createUserHandler = createUserHandler;
        _updateUserHandler = updateUserHandler;
        _deleteUserHandler = deleteUserHandler;
        _changePasswordHandler = changePasswordHandler;
        _resetPasswordHandler = resetPasswordHandler;
        _setLockoutHandler = setLockoutHandler;
        _logger = logger;
    }

    /// <summary>
    /// Get all users with pagination
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedResult<UserDto>>> GetUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 10,
        [FromQuery] string? search = null)
    {
        var result = await _getUsersHandler.HandleAsync(page, pageSize, search);
        return Ok(result);
    }

    /// <summary>
    /// Get a specific user by ID
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<UserDto>> GetUser(string id)
    {
        var user = await _getUserHandler.HandleAsync(id);
        if (user == null)
        {
            return NotFound($"User with ID '{id}' not found.");
        }
        return Ok(user);
    }

    /// <summary>
    /// Create a new user
    /// </summary>
    [HttpPost]
    public async Task<ActionResult<UserDto>> CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, user, errors) = await _createUserHandler.HandleAsync(request);

        if (!success)
        {
            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User {UserName} created successfully with ID {UserId}", user!.UserName, user.Id);
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }

    /// <summary>
    /// Update an existing user
    /// </summary>
    [HttpPut("{id}")]
    public async Task<ActionResult<UserDto>> UpdateUser(string id, [FromBody] UpdateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, user, errors) = await _updateUserHandler.HandleAsync(id, request);

        if (!success)
        {
            if (user == null)
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errors)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User {UserName} updated successfully", user!.UserName);
        return Ok(user);
    }

    /// <summary>
    /// Delete a user
    /// </summary>
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var (success, errors) = await _deleteUserHandler.HandleAsync(id);

        if (!success)
        {
            var errorsList = errors.ToList();
            if (errorsList.Any(e => e.Contains("not found")))
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errorsList)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User with ID {UserId} deleted successfully", id);
        return NoContent();
    }

    /// <summary>
    /// Change user password
    /// </summary>
    [HttpPost("{id}/change-password")]
    public async Task<IActionResult> ChangePassword(string id, [FromBody] ChangePasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, errors) = await _changePasswordHandler.HandleAsync(id, request);

        if (!success)
        {
            var errorsList = errors.ToList();
            if (errorsList.Any(e => e.Contains("not found")))
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errorsList)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Password changed successfully for user with ID {UserId}", id);
        return Ok(new { message = "Password changed successfully" });
    }

    /// <summary>
    /// Reset user password (admin function)
    /// </summary>
    [HttpPost("{id}/reset-password")]
    public async Task<IActionResult> ResetPassword(string id, [FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, errors) = await _resetPasswordHandler.HandleAsync(id, request);

        if (!success)
        {
            var errorsList = errors.ToList();
            if (errorsList.Any(e => e.Contains("not found")))
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errorsList)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("Password reset successfully for user with ID {UserId}", id);
        return Ok(new { message = "Password reset successfully" });
    }

    /// <summary>
    /// Lock/unlock user account
    /// </summary>
    [HttpPost("{id}/lockout")]
    public async Task<IActionResult> SetLockout(string id, [FromBody] SetLockoutRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var (success, action, errors) = await _setLockoutHandler.HandleAsync(id, request);

        if (!success)
        {
            var errorsList = errors.ToList();
            if (errorsList.Any(e => e.Contains("not found")))
            {
                return NotFound($"User with ID '{id}' not found.");
            }

            foreach (var error in errorsList)
            {
                ModelState.AddModelError("", error);
            }
            return BadRequest(ModelState);
        }

        _logger.LogInformation("User with ID {UserId} {Action} successfully", id, action);
        return Ok(new { message = $"User {action} successfully" });
    }
}