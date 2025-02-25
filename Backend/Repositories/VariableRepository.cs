using System.Linq.Expressions;
using ASM_Backend.Interfaces;
using ASM_Backend.Models;
using MongoDB.Driver;

namespace ASM_Backend.Repositories;

public class VariableRepository(IMongoDatabase database) : IVariableRepository
{
    private readonly IMongoCollection<Variable> _collection = database.GetCollection<Variable>("Variables");
    
    public async Task<Variable?> Get(string name)
    {
        return await _collection.Find(v => v.Name == name).FirstOrDefaultAsync();
    }
    
    public async Task Add(Variable variable)
    {
        await _collection.InsertOneAsync(variable);
    }
    
    public async Task Update(string name, Variable variable)
    {
        await _collection.ReplaceOneAsync(v => v.Name == name, variable);
    }
    
    public async Task<bool> Any(string name)
    {
        return await _collection.Find(v => v.Name == name).AnyAsync();
    }
    
    public async Task<bool> Any(Expression<Func<Variable, bool>> filter)
    {
        return await _collection.Find(filter).AnyAsync();
    }
    
    public void Dispose()
    {
    }
}