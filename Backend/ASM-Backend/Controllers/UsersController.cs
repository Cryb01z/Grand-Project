using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using ASM_Backend.Interfaces;
using ASM_Backend.Models;
using ASM_Backend.DTOs;
using ASM_Backend.Utilities;

namespace ASM_Backend.Controllers;

[Route("[controller]")]
[ApiController]
public class UsersController(IUserRepository ur) : Controller
{
    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await ur.GetAll();
        
        return Ok(users.Select(u => new { u.Id, u.Name, u.Email }));
    }
    
    [HttpGet("{id}")]
    [Authorize]
    public async Task<IActionResult> GetUser(string id)
    {
        var userIdClaim = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier);
        if ((userIdClaim == null || userIdClaim.Value != id) && !HttpContext.User.IsInRole("Admin"))
        {
            return Unauthorized();
        }

        var user = await ur.Get(id);
        
        if (user == null)
        {
            return NotFound();
        }
        
        return Ok(new { user.Id, user.Name, user.Email });
    }
    
    [HttpPut]
    [Authorize]
    public async Task<IActionResult> UpdateUser([FromBody]UpdateUserRequestDTO updateUserRequest)
    {
        var userIdClaim = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier);
        if ((userIdClaim == null || userIdClaim.Value != updateUserRequest.Id) 
            && !HttpContext.User.IsInRole("Admin"))
        {
            return Unauthorized();
        }
        
        var user = await ur.Get(updateUserRequest.Id);
        
        if (user == null)
        {
            return NotFound();
        }
        
        if (updateUserRequest.Name != null)
        {
            user.Name = updateUserRequest.Name;
        }
        
        if (updateUserRequest.Email != null)
        {
            user.Email = updateUserRequest.Email;
        }
        
        if (updateUserRequest.Password != null)
        {
            user.Password = PasswordHelper.HashPassword(updateUserRequest.Password);
        }
        
        if (updateUserRequest.Roles != null)
        {
            user.Roles = updateUserRequest.Roles;
        }

        await ur.Update(user.Id, user);

        return Ok(new UpdateUserResponseDTO
        {
            Id = user.Id,
            Name = user.Name,
            Email = user.Email,
            Roles = user.Roles
        });
    }
    
    [HttpPost]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AddUser([FromBody] AddUserRequestDTO addUserRequest)
    {
        if (await ur.Any(u => u.Email == addUserRequest.Email))
        {
            return BadRequest("User already exists");
        }
        
        var user = new User
        {
            Name = addUserRequest.Name,
            Email = addUserRequest.Email,
            Password = PasswordHelper.HashPassword(addUserRequest.Password),
            Roles = addUserRequest.Roles
        };
        
        await ur.Add(user);
        
        return Ok(new AddUserResponseDTO
        {
            Id = user.Id,
            Name = user.Name,
            Email = user.Email,
            Roles = user.Roles
        });
    }
}