using System.Linq.Expressions;
using MongoDB.Driver;

using ASM_Backend.Interfaces;
using ASM_Backend.Models;

namespace ASM_Backend.Repositories;

public class ScanResultRepository(IMongoDatabase database) : IScanResultRepository
{
    private readonly IMongoCollection<ScanResult> _collection = database.GetCollection<ScanResult>("ScanResults");
    
    public async Task<List<ScanResult>> Get(Expression<Func<ScanResult, bool>> filter, int page, int pageSize)
    {
        return await _collection.Find(filter).Skip((page - 1) * pageSize).Limit(pageSize).ToListAsync();
    }
    
    public void Dispose()
    {
    }
}