using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace ASM_Backend.Controllers;

// [Route("[controller]")]
// [ApiController]
// public class ScanResultsController(HttpClient httpClient) : Controller
// {
//     [HttpGet]
//     public async Task<IActionResult> GetAllScanResults([FromQuery]string? search, [FromQuery]int page = 1, [FromQuery, Range(1, 100)]int pageSize = 10)
//     {
//         // IQueryable<ScanResult> query = db.ScanResults;
//         //
//         // if (!string.IsNullOrWhiteSpace(search))
//         // {
//         //     query = query.Where(c => c.Domain.Contains(search));
//         // }
//         //
//         // var totalCve = await query.CountAsync();
//         // var totalPages = (int)Math.Ceiling(totalCve / (double)pageSize);
//         //
//         // // query = query.OrderByDescending(c => c.DiscoveryOn)
//         // //     .Skip((page - 1) * pageSize).Take(pageSize);
//         //
//         // query = query.Skip((page - 1) * pageSize).Take(pageSize);
//         //
//         // return Ok(new
//         // {
//         //     Page = page,
//         //     PageSize = pageSize,
//         //     PageCount = totalPages,
//         //     ScanResults = query.ToListAsync()
//         // });
//
//         return NotFound();
//     }
//     
//     [HttpGet("{domain}")]
//     public async Task<IActionResult> GetScanResult(string domain, bool returnAll = false)
//     {
//         // var query = db.ScanResults.Where(s => s.Domain == domain)
//         //     .OrderByDescending(s => s.DiscoveryOn);
//         //
//         // string serverScanResult = await httpClient.GetStringAsync($"http://171.244.21.38:65534/info/{domain}");
//         // var serverScanResultJson = JsonSerializer.Deserialize<ServerScanResult>(serverScanResult);
//         //
//         // if (query.IsNullOrEmpty() && (serverScanResultJson == null || serverScanResultJson.Status == "failed"))
//         // {
//         //     return NotFound();
//         // }
//         //
//         // if (query.IsNullOrEmpty() && serverScanResultJson != null)
//         // {
//         //     await db.ScanResults.AddAsync(serverScanResultJson.Results);
//         //     await db.SaveChangesAsync();
//         //
//         //     return Ok(serverScanResultJson.Results);
//         // }
//         //
//         // var lastScanResult = await query.FirstOrDefaultAsync();
//         // if (serverScanResultJson != null && serverScanResultJson.Results.DiscoveryOn > lastScanResult.DiscoveryOn)
//         // {
//         //     await db.ScanResults.AddAsync(serverScanResultJson.Results);
//         //     await db.SaveChangesAsync();
//         // }
//         //
//         // return returnAll ? Ok(await query.ToListAsync()) : Ok(await query.FirstOrDefaultAsync());
//
//         return NotFound();
//     }
// }