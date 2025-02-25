using System.Linq.Expressions;
using ASM_Backend.Models;

namespace ASM_Backend.Interfaces;

public interface IScanResultRepository : IDisposable
{
    Task<List<ScanResult>> Get(Expression<Func<ScanResult, bool>> filter, int page, int pageSize);
}