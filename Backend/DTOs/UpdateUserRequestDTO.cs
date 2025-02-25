using System.ComponentModel.DataAnnotations;

namespace ASM_Backend.DTOs;

public class UpdateUserRequestDTO
{
    [Required]
    public required string Id { get; set; }
    [StringLength(256, MinimumLength = 3)]
    public string? Name { get; set; }
    [EmailAddress]
    public string? Email { get; set; }
    [StringLength(256, MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string? Password { get; set; }
    public string[]? Roles { get; set; }
}