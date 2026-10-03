using SubactId.Core.Sponsors;
using SubactId.Server.Contracts;
using SubactId.Server.Tokens;
using SubactId.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Tokens.Exchange;

/// <summary>
/// The decision both grants share: a block held here refuses at once, the identity provider is
/// asked only where one is configured, and neither source can overturn the other's refusal.
/// </summary>
public class SponsorGateTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static readonly DateTimeOffset BlockedAt = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task With_no_block_and_no_upstream_the_human_may_be_acted_for()
    {
        var gate = new SponsorGate(new InMemorySponsorBlocks());

        Assert.False(gate.AsksUpstream);
        Assert.Equal(SponsorStatus.Active, await gate.GetAsync(Human, Human, TimeSpan.FromMinutes(5)));
    }

    [Theory]
    [InlineData(SponsorBlockKind.Disabled, SponsorStatus.Disabled)]
    [InlineData(SponsorBlockKind.Deleted, SponsorStatus.NotFound)]
    public async Task A_block_held_here_refuses_whether_or_not_an_identity_provider_is_asked(SponsorBlockKind kind, SponsorStatus expected)
    {
        var blocks = new InMemorySponsorBlocks();
        await blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Admin, kind, BlockedAt));

        Assert.Equal(expected, await new SponsorGate(blocks).GetAsync(Human, Human, TimeSpan.FromMinutes(5)));
        Assert.Equal(expected, await new SponsorGate(blocks, new FixedSponsorStatus(SponsorStatus.Active)).GetAsync(Human, Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task An_identity_provider_saying_the_human_is_active_does_not_lift_a_block_and_is_not_even_asked()
    {
        var blocks = new InMemorySponsorBlocks();
        await blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, BlockedAt));
        var upstream = new FixedSponsorStatus(SponsorStatus.Active);

        Assert.Equal(SponsorStatus.Disabled, await new SponsorGate(blocks, upstream).GetAsync(Human, Human, TimeSpan.FromMinutes(5)));

        // Already refused, so the provider is not asked.
        Assert.Empty(upstream.Asked);
    }

    [Theory]
    [InlineData(SponsorStatus.Active)]
    [InlineData(SponsorStatus.Disabled)]
    [InlineData(SponsorStatus.NotFound)]
    [InlineData(SponsorStatus.Unavailable)]
    public async Task With_no_block_the_identity_providers_answer_is_the_answer(SponsorStatus status)
    {
        var upstream = new FixedSponsorStatus(status);
        var gate = new SponsorGate(new InMemorySponsorBlocks(), upstream);

        Assert.True(gate.AsksUpstream);
        Assert.Equal(status, await gate.GetAsync(Human, Human, TimeSpan.FromMinutes(5)));
        Assert.Equal([Human], upstream.Asked);
        Assert.Equal([TimeSpan.FromMinutes(5)], upstream.MaxAges);
    }

    [Fact]
    public async Task The_lookup_is_by_the_sponsor_key_not_the_subject()
    {
        var blocks = new InMemorySponsorBlocks();
        await blocks.BlockAsync(new SponsorBlock("oid-1234", SponsorBlockSource.Scim, SponsorBlockKind.Disabled, BlockedAt));
        var gate = new SponsorGate(blocks);

        Assert.Equal(SponsorStatus.Disabled, await gate.GetAsync("oid-1234", Human, TimeSpan.FromMinutes(5)));
        Assert.Equal(SponsorStatus.Active, await gate.GetAsync(Human, Human, TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public async Task The_identity_provider_is_asked_by_the_subject_whatever_the_key_is()
    {
        // The provider's admin API looks users up by the identifier it issued. Any other key would
        // find nobody and refuse everybody as deleted.
        var upstream = new FixedSponsorStatus(SponsorStatus.Active);
        var blocks = new InMemorySponsorBlocks();

        Assert.Equal(SponsorStatus.Active, await new SponsorGate(blocks, upstream).GetAsync("oid-1234", Human, TimeSpan.FromMinutes(5)));

        Assert.Equal([Human], upstream.Asked);
        Assert.Equal(["oid-1234"], blocks.Asked);
    }

    [Fact]
    public void An_active_human_is_no_refusal_and_every_other_status_names_its_own_reason()
    {
        Assert.Null(SponsorGate.Refusal(SponsorStatus.Active));
        Assert.Equal((OAuthErrorResponse.AccessDenied, SponsorGate.SponsorDisabled), Coded(SponsorStatus.Disabled));
        Assert.Equal((OAuthErrorResponse.AccessDenied, SponsorGate.SponsorNotFound), Coded(SponsorStatus.NotFound));
        Assert.Equal((OAuthErrorResponse.TemporarilyUnavailable, SponsorGate.SponsorStatusUnavailable), Coded(SponsorStatus.Unavailable));
    }

    [Fact]
    public async Task A_block_may_only_be_lifted_by_the_source_that_placed_it()
    {
        var blocks = new InMemorySponsorBlocks();
        await blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, BlockedAt));

        Assert.False(await blocks.UnblockAsync(Human, SponsorBlockSource.Scim));
        Assert.Equal(SponsorStatus.Disabled, await new SponsorGate(blocks).GetAsync(Human, Human, TimeSpan.FromMinutes(5)));

        Assert.True(await blocks.UnblockAsync(Human, SponsorBlockSource.Admin));
        Assert.Equal(SponsorStatus.Active, await new SponsorGate(blocks).GetAsync(Human, Human, TimeSpan.FromMinutes(5)));
    }

    private static (string Error, string Reason) Coded(SponsorStatus status)
    {
        var refusal = SponsorGate.Refusal(status)!.Value;
        return (refusal.Error, refusal.Reason);
    }
}
