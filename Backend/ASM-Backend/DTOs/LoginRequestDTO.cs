using System.ComponentModel.DataAnnotations;

namespace ASM_Backend.DTOs;

public class LoginRequestDTO
{
    [Required]
    public required string Email { get; set; }
    [Required]
    public required string Password { get; set; }
}