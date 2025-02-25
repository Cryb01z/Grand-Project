using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace ASM_Backend.DTOs;

public class CveSearchRequestDTO
{
    public string? Search { get; set; }
    [Range(1, int.MaxValue)]
    [DefaultValue(1)]
    public int Page { get; set; } = 1;
    
    [Range(1, 100)]
    [DefaultValue(10)]
    public int PageSize { get; set; } = 10;
    
    [Range(0, 10)]
    public double? ScoreFrom { get; set; }
    
    [Range(0, 10)]
    public double? ScoreTo { get; set; }
}