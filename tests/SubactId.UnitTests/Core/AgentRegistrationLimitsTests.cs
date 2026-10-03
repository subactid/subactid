using SubactId.Core.Agents;
using SubactId.UnitTests.Tokens.ClientAuth;
using Xunit;

namespace SubactId.UnitTests.Core;

/// <summary>
/// The bounds a registration is held to, and the default lifetimes. They are configuration, so
/// any contradiction among them is reported at startup.
/// </summary>
public class AgentRegistrationLimitsTests
{
    private static readonly AgentRegistrationLimits Default = AgentRegistrationLimits.Default;

    [Fact]
    public void Bound_holds_an_agent_to_the_current_maximums_and_leaves_one_within_them_alone()
    {
        var limits = Default with { MaxTaskTtl = TimeSpan.FromMinutes(20), MaxTokenTtl = TimeSpan.FromMinutes(2) };
        var looser = ClientAuthTestData.Agent() with { MaxTaskTtl = TimeSpan.FromHours(1), MaxTokenTtl = TimeSpan.FromMinutes(10) };
        var within = ClientAuthTestData.Agent() with { MaxTaskTtl = TimeSpan.FromMinutes(10), MaxTokenTtl = TimeSpan.FromMinutes(1) };

        var bound = limits.Bound(looser);

        Assert.Equal((TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(2)), (bound.MaxTaskTtl, bound.MaxTokenTtl));
        Assert.Equal(looser with { MaxTaskTtl = bound.MaxTaskTtl, MaxTokenTtl = bound.MaxTokenTtl }, bound);
        Assert.Same(within, limits.Bound(within));
    }

    [Fact]
    public void The_shipped_defaults_do_not_contradict_each_other()
    {
        Assert.Empty(Default.Contradictions());
    }

    [Fact]
    public void The_shipped_defaults_are_the_ones_the_documentation_names()
    {
        Assert.Equal(TimeSpan.FromMinutes(1), Default.MinTaskTtl);
        Assert.Equal(TimeSpan.FromDays(1), Default.MaxTaskTtl);
        Assert.Equal(TimeSpan.FromSeconds(30), Default.MinTokenTtl);
        Assert.Equal(TimeSpan.FromHours(1), Default.MaxTokenTtl);
        Assert.Equal(TimeSpan.FromMinutes(30), Default.DefaultTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(5), Default.DefaultTokenTtl);
    }

    [Fact]
    public void A_smallest_longer_than_its_largest_is_reported()
    {
        Assert.Contains(
            "the smallest task lifetime is longer than the largest",
            (Default with { MinTaskTtl = TimeSpan.FromDays(2) }).Contradictions());

        Assert.Contains(
            "the smallest token lifetime is longer than the largest",
            (Default with { MinTokenTtl = TimeSpan.FromHours(2) }).Contradictions());
    }

    [Fact]
    public void A_token_floor_above_the_task_floor_leaves_the_shortest_task_unusable()
    {
        // A token may never outlive its task, so a registration at the shortest allowed task
        // length could satisfy neither bound at once.
        var impossible = Default with { MinTaskTtl = TimeSpan.FromMinutes(1), MinTokenTtl = TimeSpan.FromMinutes(5) };

        Assert.Contains(
            "the smallest token lifetime is longer than the smallest task lifetime, which no registration at that task lifetime could satisfy",
            impossible.Contradictions());
    }

    [Fact]
    public void A_default_outside_the_bounds_is_reported()
    {
        // Left unreported, every registration that omits a lifetime would be refused.
        Assert.Contains(
            "the default task lifetime is outside the allowed task lifetimes",
            (Default with { MaxTaskTtl = TimeSpan.FromMinutes(10) }).Contradictions());

        Assert.Contains(
            "the default token lifetime is outside the allowed token lifetimes",
            (Default with { MaxTokenTtl = TimeSpan.FromMinutes(1) }).Contradictions());
    }

    [Fact]
    public void The_two_defaults_are_not_checked_against_each_other_here()
    {
        // A default token lifetime longer than the default task's is harmless, because the shorter
        // is taken. The loader reports it against the two settings, so it is not repeated here.
        var longToken = Default with { DefaultTaskTtl = TimeSpan.FromMinutes(2), DefaultTokenTtl = TimeSpan.FromMinutes(5) };

        Assert.Empty(longToken.Contradictions());
    }
}
