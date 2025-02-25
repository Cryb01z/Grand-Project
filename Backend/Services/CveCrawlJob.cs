using System.Globalization;
using System.Text.Json;
using System.Timers;
using Timer = System.Timers.Timer;

using MongoDB.Bson;

using ASM_Backend.Interfaces;
using ASM_Backend.Models;

namespace ASM_Backend.Services;

public class CveCrawlJob(IServiceProvider serviceProvider,ILogger<CveCrawlJob> logger) : IHostedService, IDisposable
{
    const string NvdCveApi = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const string NvdCveChangeApi = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0";
    const string NvdApiKey = "851b2354-0b64-44bc-b1a5-ff48b53c13cb";
    
    private readonly HttpClient _httpClient = new();
    
    private Timer? _timer;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _timer = new Timer(TimeSpan.FromSeconds(10));
        _timer.AutoReset = false;
        _timer.Elapsed += StartExecution;
        _timer.Start();
        
        return Task.CompletedTask;
    }
    
    private async void StartExecution(object? sender, ElapsedEventArgs? e)
    {
        using var scope = serviceProvider.CreateScope();
        var cr = scope.ServiceProvider.GetRequiredService<ICveRepository>();
        var vr = scope.ServiceProvider.GetRequiredService<IVariableRepository>();
        
        _httpClient.DefaultRequestHeaders.Add("apiKey", NvdApiKey);
        _httpClient.Timeout = TimeSpan.FromMinutes(5);
        
        await DoWork(cr, vr);
    }
    
    private string GetCurrentTime()
    {
        return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fff", CultureInfo.InvariantCulture);
    }
    
    private async Task UpdateLastCrawlTime(IVariableRepository vr, string currentTime)
    {
        var lastCrawlTimeVar = await vr.Get("LastCrawlTime");
        if (lastCrawlTimeVar == null)
        {
            await vr.Add(new Variable
            {
                Id = ObjectId.GenerateNewId().ToString(),
                Name = "LastCrawlTime",
                Value = currentTime,
            });
        }
        else
        {
            lastCrawlTimeVar.Value = currentTime;
            await vr.Update("LastCrawlTime", lastCrawlTimeVar);
        }
    }
    
    private async Task<T> GetFromNist<T>(string url)
    {
        int httpRetryCount = 0;
        while (true)
        {
            try
            {
                string response = await _httpClient.GetStringAsync(url);
        
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                };
                
                var result = JsonSerializer.Deserialize<T>(response, options) 
                             ?? throw new Exception("Failed to deserialize json");
                
                if (httpRetryCount > 0)
                {
                    logger.LogWarning($"Nist request retried {httpRetryCount} times!!!");
                }
                
                return result;
            }
            catch (HttpRequestException)
            {
                httpRetryCount++;
                Thread.Sleep(5000);
            }
        }
    }

    private async Task CrawlAllCves(ICveRepository cr, string lastCrawlTime, string currentTime)
    {
        uint startIndex = 0;
        uint totalResults;
        do
        {
            string url = $"{NvdCveApi}?startIndex={startIndex}";

            if (lastCrawlTime != currentTime)
            {
                url += $"&lastModStartDate={lastCrawlTime}&lastModEndDate={currentTime}";
            }
                
            var nistFeed = await GetFromNist<NvdCveFeed>(url);

            var cves = nistFeed.Vulnerabilities.Select(v => v.Cve)
                .ToList();

            if (cves.Count != 0)
                await cr.UpdateMany(cves);
                
            logger.LogInformation($"Crawled {startIndex + cves.Count} cves from NVD feed");

            startIndex += (uint)nistFeed.ResultsPerPage;
            totalResults = (uint)nistFeed.TotalResults;

            Thread.Sleep(5000);
        } while (startIndex < totalResults);
        
        logger.LogInformation($"Finished crawling {totalResults} cves from NVD feed");
    }
    
    private async Task CrawlAllCveChanges(ICveRepository cr, string lastCrawlTime, string currentTime)
    {
        uint startIndex = 0;
        uint totalResults;
        do
        {
            string url = $"{NvdCveChangeApi}?startIndex={startIndex}";

            if (lastCrawlTime != currentTime)
            {
                url += $"&changeStartDate={lastCrawlTime}&changeEndDate={currentTime}";
            }
                
            var nistFeed = await GetFromNist<NvdCveChangeFeed>(url);

            var cveChanges = nistFeed.CveChanges.Select(v => v.Change)
                .ToList();

            if (cveChanges.Count != 0)
                await cr.AddChangeMany(cveChanges);
                
            logger.LogInformation($"Crawled {startIndex + cveChanges.Count} cve changes from NVD feed");

            startIndex += (uint)nistFeed.ResultsPerPage;
            totalResults = (uint)nistFeed.TotalResults;

            Thread.Sleep(5000);
        } while (startIndex < totalResults);
        
        logger.LogInformation($"Finished crawling {totalResults} cve changes from NVD feed");
    }

    private async Task DoWork(ICveRepository cr, IVariableRepository vr)
    {
        logger.LogInformation("Start crawling job!!!");
        
        var currentTime = GetCurrentTime();
        var lastCrawlTime = currentTime;
        
        var lastCrawlTimeVar = await vr.Get("LastCrawlTime");
        if (lastCrawlTimeVar != null)
        {
            lastCrawlTime = lastCrawlTimeVar.Value;
        }
        
        bool done = false;

        try
        {
            await CrawlAllCves(cr, lastCrawlTime, currentTime);
            await CrawlAllCveChanges(cr, lastCrawlTime, currentTime);
            done = true;
        }
        catch (Exception e)
        {
            logger.LogError(e, "Failed to crawl cves from NVD feed");
        }
        finally
        {
            if (done) await UpdateLastCrawlTime(vr, currentTime);

            if (_timer != null)
            {
                _timer.Interval = TimeSpan.FromHours(1).TotalMilliseconds;
                _timer.Start();
            }
            
            logger.LogInformation("Finished crawling job!!!");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Stop();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}