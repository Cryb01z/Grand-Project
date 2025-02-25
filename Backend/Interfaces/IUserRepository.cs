using System.Linq.Expressions;

using ASM_Backend.Models;

namespace ASM_Backend.Interfaces;

public interface IUserRepository : IDisposable
{
    Task<List<User>> GetAll();
    Task<User?> Get(string id);
    Task<List<User>> Get(Expression<Func<User, bool>> filter);
    Task Add(User user);
    Task Update(string id, User user);
    Task<bool> Any(Expression<Func<User, bool>> filter);
    Task<long> Count();
    Task<long> Count(Expression<Func<User, bool>> filter);
}