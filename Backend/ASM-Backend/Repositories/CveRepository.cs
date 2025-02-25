using System.Linq.Expressions;
using MongoDB.Driver;

using ASM_Backend.Interfaces;
using ASM_Backend.Models;

namespace ASM_Backend.Repositories;

public class CveRepository(IMongoDatabase database) : ICveRepository
{
    private readonly IMongoCollection<Cve> _collection = database.GetCollection<Cve>("Cves");
    
    public async Task<List<Cve>> GetAll()
    {
        return await _collection.Find(_ => true).ToListAsync();
    }
    
    public async Task<Cve?> Get(string id)
    {
        return await _collection.Find(cve => cve.Id == id).FirstOrDefaultAsync();
    }
    
    public async Task<List<Cve>> Get(Expression<Func<Cve, bool>> filter)
    {
        return await _collection.Find(filter).ToListAsync();
    }
    
    public async Task<List<Cve>> Get(FilterDefinition<Cve> filter)
    {
        return await _collection.Find(filter).ToListAsync();
    }
    
    public async Task<List<Cve>> Get(Expression<Func<Cve, bool>> filter, int page, int pageSize)
    {
        return await _collection.Find(filter).Skip((page - 1) * pageSize).Limit(pageSize).ToListAsync();
    }
    
    public async Task<List<Cve>> Get(FilterDefinition<Cve> filter, int page, int pageSize)
    {
        return await _collection.Find(filter).SortByDescending(cve => cve.LastModified)
            .Skip((page - 1) * pageSize).Limit(pageSize).ToListAsync();
    }
    
    public async Task Add(Cve cve)
    {
        await _collection.InsertOneAsync(cve);
    }
    
    public async Task AddMany(IEnumerable<Cve> cves)
    {
        await _collection.InsertManyAsync(cves);
    }
    
    public async Task AddChange(string id, Change change)
    {
        var update = Builders<Cve>.Update.Push(c => c.Changes, change);
        await _collection.UpdateOneAsync(c => c.Id == id, update);
    }

    public async Task AddChangeMany(IEnumerable<Change> changes)
    {
        var updates = new List<WriteModel<Cve>>();
        var filterBuilder = Builders<Cve>.Filter;
        
        foreach (var change in changes)
        {
            var filter = filterBuilder.Eq(c => c.Id, change.CveId);
            var update = Builders<Cve>.Update.AddToSet(c => c.Changes, change);
            
            updates.Add(new UpdateOneModel<Cve>(filter, update));
        }
        
        await _collection.BulkWriteAsync(updates);
    }
    
    public async Task Update(string id, Cve cve)
    {
        await _collection.ReplaceOneAsync(c => c.Id == id, cve);
    }
    
    public async Task UpdateMany(IEnumerable<Cve> cves)
    {
        var updates = new List<WriteModel<Cve>>();
        var filterBuilder = Builders<Cve>.Filter;
        
        foreach (var cve in cves)
        {
            var filter = filterBuilder.Eq(c => c.Id, cve.Id);
            var update = new ReplaceOneModel<Cve>(filter, cve)
            {
                IsUpsert = true
            };
            
            updates.Add(update);
        }
        await _collection.BulkWriteAsync(updates);
    }
    
    public async Task<bool> Any(Expression<Func<Cve, bool>> filter)
    {
        return await _collection.Find(filter).AnyAsync();
    }
    
    public async Task<long> Count()
    {
        return await _collection.CountDocumentsAsync(_ => true);
    }
    
    public async Task<long> Count(Expression<Func<Cve, bool>> filter)
    {
        return await _collection.CountDocumentsAsync(filter);
    }
    
    public async Task<long> Count(FilterDefinition<Cve> filter)
    {
        return await _collection.CountDocumentsAsync(filter);
    }
    
    public async Task<List<Cve>> Search(string search, int page, int pageSize)
    {
        var filter = Builders<Cve>.Filter.Text(search);
        
        var sort = Builders<Cve>.Sort.MetaTextScore("textScore");
        
        return await _collection.Find(filter).Sort(sort)
            .Skip((page - 1) * pageSize).Limit(pageSize).ToListAsync();
    }
    
    public async Task<long> CountSearch(string search)
    {
        var filter = Builders<Cve>.Filter.Text(search);
        
        return await _collection.CountDocumentsAsync(filter);
    }
    
    public void Dispose()
    {
    }
}