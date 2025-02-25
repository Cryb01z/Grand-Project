using System.Linq.Expressions;
using ASM_Backend.Interfaces;
using ASM_Backend.Models;
using MongoDB.Driver;

namespace ASM_Backend.Repositories;

public class UserRepository(IMongoDatabase database) : IUserRepository
{
    private readonly IMongoCollection<User> _collection = database.GetCollection<User>("Users");

    public async Task<List<User>> GetAll()
    {
        return await _collection.Find(_ => true).ToListAsync();
    }

    public async Task<User?> Get(string id)
    {
        return await _collection.Find(user => user.Id == id).FirstOrDefaultAsync();
    }

    public async Task<List<User>> Get(Expression<Func<User, bool>> filter)
    {
        return await _collection.Find(filter).ToListAsync();
    }

    public async Task<List<User>> Get(Expression<Func<User, bool>> filter, int page, int pageSize)
    {
        return await _collection.Find(filter).Skip((page - 1) * pageSize).Limit(pageSize).ToListAsync();
    }

    public async Task Add(User user)
    {
        await _collection.InsertOneAsync(user);
    }

    public async Task Update(string id, User user)
    {
        await _collection.ReplaceOneAsync(u => u.Id == id, user);
    }

    public async Task<bool> Any(Expression<Func<User, bool>> filter)
    {
        return await _collection.Find(filter).AnyAsync();
    }

    public async Task<long> Count()
    {
        return await _collection.CountDocumentsAsync(_ => true);
    }

    public async Task<long> Count(Expression<Func<User, bool>> filter)
    {
        return await _collection.CountDocumentsAsync(filter);
    }

    public void Dispose()
    {
    }
}