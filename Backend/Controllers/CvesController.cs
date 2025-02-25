using Microsoft.AspNetCore.Mvc;

using MongoDB.Driver;

using ASM_Backend.DTOs;
using ASM_Backend.Interfaces;
using ASM_Backend.Models;
using MongoDB.Bson;

namespace ASM_Backend.Controllers;

[Route("[controller]")]
[ApiController]
public class CvesController(ICveRepository cr) : Controller
{
    [HttpGet]
    public async Task<IActionResult> GetAllCves([FromQuery]CveSearchRequestDTO searchRequest)
    {
        if (searchRequest.ScoreFrom > searchRequest.ScoreTo)
        {
            return BadRequest("ScoreFrom must be less than or equal to ScoreTo");
        }
        
        var filter = Builders<Cve>.Filter.Empty;
        if (!string.IsNullOrWhiteSpace(searchRequest.Search))
        {
            filter = Builders<Cve>.Filter.Regex(c => c.Id, 
                new BsonRegularExpression(searchRequest.Search, "i"));
        }
        
        #pragma warning disable CS8602 // Dereference of a possibly null reference.
        if (searchRequest.ScoreFrom != null)
        {
            var filterScoreV2 = Builders<Cve>.Filter.Gte(c =>
                c.Metrics.CvssMetricV2[0].CvssData.BaseScore, searchRequest.ScoreFrom);
            var filterScoreV3 = Builders<Cve>.Filter.Gte(c =>
                c.Metrics.CvssMetricV30[0].CvssData.BaseScore, searchRequest.ScoreFrom);
            var filterScoreV31 = Builders<Cve>.Filter.Gte(c =>
                c.Metrics.CvssMetricV31[0].CvssData.BaseScore, searchRequest.ScoreFrom);
            
            filter &= (filterScoreV2 | filterScoreV3 | filterScoreV31);
        }
        
        if (searchRequest.ScoreTo != null)
        {
            var filterScoreV2 = Builders<Cve>.Filter.Lte(c =>
                c.Metrics.CvssMetricV2[0].CvssData.BaseScore, searchRequest.ScoreTo);
            var filterScoreV3 = Builders<Cve>.Filter.Lte(c =>
                c.Metrics.CvssMetricV30[0].CvssData.BaseScore, searchRequest.ScoreTo);
            var filterScoreV31 = Builders<Cve>.Filter.Lte(c =>
                c.Metrics.CvssMetricV31[0].CvssData.BaseScore, searchRequest.ScoreTo);

            filter &= (filterScoreV2 | filterScoreV3 | filterScoreV31);
        }
        #pragma warning restore CS8602 // Dereference of a possibly null reference.
        
        var totalCve = await cr.Count(filter);
        
        var totalPages = (int)Math.Ceiling(totalCve / (double)searchRequest.PageSize);
        
        List<Cve> cves = await cr.Get(filter, searchRequest.Page, searchRequest.PageSize);
        
        var cveList = new List<object>();
        foreach (var cve in cves)
        {
            cveList.Add(new
            {
                id = cve.Id,
                descriptions = cve.Descriptions,
                configurations = cve.Configurations,
                lastModified = cve.LastModified,
                scoreV20 = cve.Metrics?.CvssMetricV2?[0].CvssData.BaseScore,
                scoreV30 = cve.Metrics?.CvssMetricV30?[0].CvssData.BaseScore,
                scoreV31 = cve.Metrics?.CvssMetricV31?[0].CvssData.BaseScore
            });
        }
        
        return Ok(new SearchResponseDTO
        {
            Page = searchRequest.Page,
            PageSize = searchRequest.PageSize,
            PageCount = totalPages, 
            Data = cveList
        });
    }
    
    [HttpGet("{id}")]
    public async Task<IActionResult> GetCve(string id)
    {
        var cve = await cr.Get(id);
        
        if (cve == null)
        {
            return NotFound();
        }
        
        return Ok(cve);
    }
    
    [HttpGet("Count")]
    public async Task<IActionResult> Count()
    {
        return Ok(new CountResponseDTO
        {
            Count = await cr.Count()
        });
    }
}