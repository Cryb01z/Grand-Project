namespace ASM_Backend.DTOs;

public class AddUserRequestDTO
{
    public required string Name { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string[] Roles { get; set; }
}