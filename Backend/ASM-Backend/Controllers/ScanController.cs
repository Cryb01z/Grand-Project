using Microsoft.AspNetCore.Mvc;

namespace ASM_Backend.Controllers;

public class ScanController(HttpClient httpClient) : Controller
{
    [HttpGet("Start/{domain}")]
    public async Task<IActionResult> Scan(string domain, bool rescan = false)
    {
        var response = await httpClient.GetAsync($"http://171.244.21.38:65534/scan/{domain}");

        return Ok(await response.Content.ReadAsStringAsync());
    }

    [HttpGet("Status/{domain}")]
    public async Task<IActionResult> Status(string domain)
    {
        var response = await httpClient.GetAsync($"http://171.244.21.38:65534/scan/{domain}/status");

        return Ok(await response.Content.ReadAsStringAsync());
    }
}