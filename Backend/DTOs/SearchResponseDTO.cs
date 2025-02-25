namespace ASM_Backend.DTOs;

public class SearchResponseDTO
{
    public required int Page { get; set; }
    public required int PageSize { get; set; }
    public required int PageCount { get; set; }
    public List<object>? Data { get; set; }
}