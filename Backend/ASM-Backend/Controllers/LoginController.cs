using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using ASM_Backend.Models;
using ASM_Backend.DTOs;
using ASM_Backend.Interfaces;
using ASM_Backend.Utilities;

namespace ASM_Backend.Controllers;

[Route("[controller]")]
[ApiController]
public class LoginController(IConfiguration configuration, IUserRepository ur) : Controller
{
    private readonly string _key = configuration["Jwt:Secret"] ?? "this is totally a secret key";
    private readonly string _issuer = configuration["Jwt:Issuer"] ?? "https://api.caasm.tech/";
    private readonly string _audience = configuration["Jwt:Audience"] ?? "https://api.caasm.tech/";

    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginRequestDTO loginRequest)
    {
        var validUser = await ur.Get(u => u.Email == loginRequest.Email);
        
        if (!validUser.Any())
        {
            return Unauthorized();
        }
        
        var user = validUser.First();
        
        if (!PasswordHelper.VerifyPassword(loginRequest.Password, user.Password))
        {
            return Unauthorized();
        }

        var loginToken = JwtHelper.CreateToken(_key, _issuer, _audience, user);

        return Ok(new LoginResponseDTO
        {
            Token = loginToken
        });
    }
    
    [AllowAnonymous]
    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDTO registerRequest)
    {
        if (await ur.Any(u => u.Email == registerRequest.Email))
        {
            return BadRequest("User already exists");
        }
        
        var user = new User
        {
            Name = registerRequest.Name,
            Email = registerRequest.Email,
            Password = PasswordHelper.HashPassword(registerRequest.Password),
            Roles = ["User"]
        };

        await ur.Add(user);

        return Ok(new RegisterResponseDTO
        {
            Id = user.Id,
            Name = user.Name,
            Email = user.Email
        });
    }
}