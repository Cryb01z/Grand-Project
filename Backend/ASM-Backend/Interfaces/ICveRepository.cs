using System.Linq.Expressions;

using ASM_Backend.Models;
using MongoDB.Driver;

namespace ASM_Backend.Interfaces;

public interface ICveRepository : IDisposable
{
    Task<List<Cve>> GetAll();
    Task<Cve?> Get(string id);
    Task<List<Cve>> Get(Expression<Func<Cve, bool>> filter);
    Task<List<Cve>> Get(FilterDefinition<Cve> filter);
    Task<List<Cve>> Get(Expression<Func<Cve, bool>> filter, int page, int pageSize);
    Task<List<Cve>> Get(FilterDefinition<Cve> filter, int page, int pageSize);
    Task Add(Cve cve);
    Task AddMany(IEnumerable<Cve> cves);
    Task AddChange(string id, Change change);
    Task AddChangeMany(IEnumerable<Change> changes);
    Task Update(string id, Cve cve);
    Task UpdateMany(IEnumerable<Cve> cves);
    Task<bool> Any(Expression<Func<Cve, bool>> filter);
    Task<long> Count();
    Task<long> Count(Expression<Func<Cve, bool>> filter);
    Task<long> Count(FilterDefinition<Cve> filter);
    Task<List<Cve>> Search(string search, int page, int pageSize);
    Task<long> CountSearch(string search);
}