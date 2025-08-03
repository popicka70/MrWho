using Microsoft.AspNetCore.Authorization;
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
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        IGetUsersHandler getUsersHandler,
        IGetUserHandler getUserHandler,
        ILogger<UsersController> logger)
    {
        _getUsersHandler = getUsersHandler;
        _getUserHandler = getUserHandler;
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

    // TODO: Implement remaining user management endpoints when handlers are created
    // - CreateUser
    // - UpdateUser  
    // - DeleteUser
    // - ChangePassword
    // - ResetPassword
    // - SetLockout
}