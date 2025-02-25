namespace ASM_Backend.DTOs;

public class AddUserResponseDTO
{
    public required string Id { get; set; }
    public required string Name { get; set; }
    public required string Email { get; set; }
    public required string[] Roles { get; set; }
}