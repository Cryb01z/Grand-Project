using System.Linq.Expressions;

using ASM_Backend.Models;

namespace ASM_Backend.Interfaces;

public interface IVariableRepository : IDisposable
{
    Task<Variable?> Get(string name);
    
    Task Add(Variable variable);
    
    Task Update(string name, Variable variable);
    
    Task<bool> Any(string name);
    
    Task<bool> Any(Expression<Func<Variable, bool>> filter);
}