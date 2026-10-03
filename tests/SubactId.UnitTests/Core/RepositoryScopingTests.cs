using System.Reflection;
using SubactId.Core.Delegation;
using Xunit;

namespace SubactId.UnitTests.Core;

/// <summary>
/// Tripwire for the rule that every query touching tasks or grants is filtered by agent.
/// A new method on either interface without an <c>agentId</c> parameter fails this test;
/// <c>AddAsync</c> is exempt because the entity it stores carries the agent id itself.
/// </summary>
public class RepositoryScopingTests
{
    [Theory]
    [InlineData(typeof(ITaskRepository))]
    [InlineData(typeof(ITaskGrantRepository))]
    public void Every_query_on_agent_scoped_repositories_takes_the_agent_id(Type repository)
    {
        var unscoped = repository.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name != "AddAsync")
            .Where(m => !m.GetParameters().Any(p => p.Name == "agentId" && p.ParameterType == typeof(string)))
            .Select(m => m.Name)
            .ToList();

        Assert.Empty(unscoped);
    }

    [Fact]
    public void Entities_stored_by_agent_scoped_repositories_carry_the_agent_id()
    {
        Assert.NotNull(typeof(DelegationTask).GetProperty(nameof(DelegationTask.AgentId)));
        Assert.NotNull(typeof(TaskGrant).GetProperty(nameof(TaskGrant.AgentId)));
    }
}
