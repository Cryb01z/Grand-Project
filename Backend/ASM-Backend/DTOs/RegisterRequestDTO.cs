using System.ComponentModel.DataAnnotations;

namespace ASM_Backend.DTOs;

public class RegisterRequestDTO
{
    [Required]
    [StringLength(256, MinimumLength = 3)]
    public required string Name { get; set; }
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    [Required]
    [StringLength(256, MinimumLength = 6)]
    [DataType(DataType.Password)]
    public required string Password { get; set; }
}