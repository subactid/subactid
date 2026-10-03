using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SubactId.Core.Sponsors;
using SubactId.Server.Configuration;
using SubactId.Server.Logout;
using SubactId.Server.Tokens;
using SubactId.Server.Upstream;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Hosting;

/// <summary>
/// What the container holds in each sponsor check mode. In <c>signals</c> mode nothing may be able
/// to ask the identity provider about a human.
/// </summary>
public class UpstreamIdpRegistrationTests
{
    [Fact]
    public void Poll_mode_registers_the_outbound_check_and_a_gate_that_uses_it()
    {
        using var provider = Build(SponsorCheckMode.Poll);

        Assert.NotNull(provider.GetService<ISponsorStatusSource>());

        using var scope = provider.CreateScope();
        Assert.True(scope.ServiceProvider.GetRequiredService<SponsorGate>().AsksUpstream);
    }

    [Fact]
    public void Signals_mode_registers_no_way_to_reach_the_identity_provider_about_a_human()
    {
        using var provider = Build(SponsorCheckMode.Signals);

        Assert.Null(provider.GetService<ISponsorStatusSource>());

        using var scope = provider.CreateScope();
        Assert.False(scope.ServiceProvider.GetRequiredService<SponsorGate>().AsksUpstream);
    }

    [Fact]
    public void The_subject_token_validator_is_built_in_both_modes()
    {
        // Signals mode stops the control plane asking about a human. It still checks that their token
        // is real, as in both modes.
        foreach (var mode in (SponsorCheckMode[])[SponsorCheckMode.Poll, SponsorCheckMode.Signals])
        {
            using var provider = Build(mode);
            Assert.NotNull(provider.GetService<UpstreamTokenValidator>());
        }
    }

    [Fact]
    public void The_logout_receiver_is_registered_only_when_an_audience_is_configured()
    {
        // No audience means no endpoint and no validator: a receiver that cannot check who a
        // token was meant for would accept anything the provider ever signed.
        var services = new ServiceCollection();
        services.AddSingleton(SigningKeySet.CreateEphemeral());
        services.AddScoped<ISponsorRepository, InMemorySponsorBlocks>();
        services.AddUpstreamIdp(Upstream(SponsorCheckMode.Signals, logoutAudience: null));
        services.AddSubactIdLogout(Upstream(SponsorCheckMode.Signals, logoutAudience: null));
        using var without = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

        Assert.Null(without.GetService<LogoutTokenValidator>());
        using (var scope = without.CreateScope())
        {
            Assert.Null(scope.ServiceProvider.GetService<LogoutService>());
        }

        var configured = new ServiceCollection();
        configured.AddSingleton(SigningKeySet.CreateEphemeral());
        configured.AddScoped<ISponsorRepository, InMemorySponsorBlocks>();
        configured.AddUpstreamIdp(Upstream(SponsorCheckMode.Signals, logoutAudience: "workbench"));
        configured.AddSubactIdLogout(Upstream(SponsorCheckMode.Signals, logoutAudience: "workbench"));
        using var with = configured.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        Assert.NotNull(with.GetService<LogoutTokenValidator>());
    }

    [Fact]
    public void The_key_refresher_is_built_without_a_clock_in_the_container()
    {
        // The rest of this file builds containers without a TimeProvider, and AddUpstreamIdp falls
        // back when there is none. This resolves the refresher, so a hosted service that required the
        // clock would fail here.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(SigningKeySet.CreateEphemeral());
        services.AddScoped<ISponsorRepository, InMemorySponsorBlocks>();
        services.AddUpstreamIdp(Upstream(SponsorCheckMode.Signals));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

        Assert.Single(provider.GetServices<IHostedService>().OfType<UpstreamKeyRefresher>());
    }

    /// <summary>These registrations as <c>Program</c> makes them, with only what they need around them.</summary>
    private static ServiceProvider Build(SponsorCheckMode mode)
    {
        var services = new ServiceCollection();
        services.AddSingleton(SigningKeySet.CreateEphemeral());
        services.AddScoped<ISponsorRepository, InMemorySponsorBlocks>();
        services.AddUpstreamIdp(Upstream(mode));

        // The same validation the host runs, so an unsatisfiable lifetime fails here rather than on
        // the first request.
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    private static UpstreamIdpOptions Upstream(SponsorCheckMode mode, string? logoutAudience = null) =>
        new()
        {
            MetadataUrl = new Uri("https://idp.example.test/realms/main/.well-known/openid-configuration"),
            Audience = "subactid",
            SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim,
            SponsorCheckMode = mode,
            SponsorCheck = mode == SponsorCheckMode.Poll
                ? new SponsorCheckOptions
                {
                    UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"),
                    TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"),
                    ClientId = "subactid",
                    CacheTtl = TimeSpan.FromSeconds(30),
                }
                : null,
            BackchannelLogout = logoutAudience is null ? null : new BackchannelLogoutOptions { Audience = logoutAudience },
        };
}
