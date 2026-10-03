using Microsoft.Extensions.Configuration;
using SubactId.Core.Agents;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Configuration;

public class SubactIdOptionsLoaderTests
{
    private const string ConnectionStringSentinel = "Host=db;Password=SENTINEL-DO-NOT-LEAK";

    private static readonly string[] SponsorCheckKeys =
    [
        "SubactId:UpstreamIdp:SponsorCheck:UsersUrl",
        "SubactId:UpstreamIdp:SponsorCheck:TokenUrl",
        "SubactId:UpstreamIdp:SponsorCheck:ClientId",
        "SubactId:UpstreamIdp:SponsorCheck:CacheTtl",
    ];

    private static readonly Dictionary<string, string?> Complete = new()
    {
        ["SubactId:Issuer"] = "https://subactid.example.test",
        ["SubactId:UpstreamIdp:MetadataUrl"] = "https://idp.example.test/realms/main/.well-known/openid-configuration",
        ["SubactId:UpstreamIdp:Audience"] = "subactid",
        ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
        ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = "https://idp.example.test/realms/main/protocol/openid-connect/token",
        ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
        ["SubactId:Database:ConnectionString"] = ConnectionStringSentinel,
    };

    [Fact]
    public void Empty_configuration_reports_every_required_key_by_name()
    {
        var result = SubactIdOptionsLoader.Load(Build([]));

        Assert.False(result.IsValid);
        Assert.Null(result.Options);
        Assert.Collection(
            result.Errors,
            e => Assert.StartsWith("SubactId:Issuer (environment variable SubactId__Issuer) is required.", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:UpstreamIdp:Issuer (environment variable SubactId__UpstreamIdp__Issuer) is required:", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:UpstreamIdp:Audience (environment variable SubactId__UpstreamIdp__Audience) is required.", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:UpstreamIdp:SponsorCheck:UsersUrl (environment variable SubactId__UpstreamIdp__SponsorCheck__UsersUrl) is required.", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:UpstreamIdp:SponsorCheck:TokenUrl (environment variable SubactId__UpstreamIdp__SponsorCheck__TokenUrl) is required.", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:UpstreamIdp:SponsorCheck:ClientId (environment variable SubactId__UpstreamIdp__SponsorCheck__ClientId) is required.", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:Database:ConnectionString (environment variable SubactId__Database__ConnectionString) is required.", e, StringComparison.Ordinal));
    }

    [Fact]
    public void Complete_configuration_is_valid_and_applies_ttl_defaults()
    {
        var result = SubactIdOptionsLoader.Load(Build(Complete));

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        var options = Assert.IsType<SubactIdOptions>(result.Options);
        Assert.Equal(new Uri("https://subactid.example.test"), options.Issuer);
        Assert.Equal(new Uri("https://idp.example.test/realms/main/.well-known/openid-configuration"), options.UpstreamIdp.MetadataUrl);
        Assert.Equal(ConnectionStringSentinel, options.Database.ConnectionString);
        Assert.Equal(TimeSpan.FromMinutes(30), options.Tokens.DefaultTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(5), options.Tokens.DefaultTokenTtl);
    }

    [Fact]
    public void Migration_connection_string_is_optional_and_defaults_to_null()
    {
        var result = SubactIdOptionsLoader.Load(Build(Complete));

        Assert.True(result.IsValid);
        Assert.Null(result.Options!.Database.MigrationConnectionString);
    }

    [Theory]
    [InlineData("Host=db;Username=owner;Password=SENTINEL-MIGRATION", "Host=db;Username=owner;Password=SENTINEL-MIGRATION")]
    [InlineData("   ", null)]
    public void Migration_connection_string_is_used_when_present(string configured, string? expected)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Database:MigrationConnectionString", configured))));

        Assert.True(result.IsValid);
        Assert.Equal(expected, result.Options!.Database.MigrationConnectionString);
        Assert.DoesNotContain("SENTINEL", result.Options.Database.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Explicit_ttls_are_honoured()
    {
        var config = With(("SubactId:Tokens:DefaultTaskTtl", "01:00:00"), ("SubactId:Tokens:DefaultTokenTtl", "00:10:00"));

        var result = SubactIdOptionsLoader.Load(Build(config));

        Assert.True(result.IsValid);
        Assert.Equal(TimeSpan.FromHours(1), result.Options!.Tokens.DefaultTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(10), result.Options.Tokens.DefaultTokenTtl);
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    [InlineData("ftp://subactid.example.test")]
    public void Issuer_must_be_an_absolute_http_url(string issuer)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Issuer", issuer))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("SubactId:Issuer", error, StringComparison.Ordinal);
        Assert.Contains("absolute http or https URL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Metadata_url_must_be_an_absolute_http_url()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:UpstreamIdp:MetadataUrl", "idp.example.test"))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("SubactId:UpstreamIdp:MetadataUrl", error, StringComparison.Ordinal);
    }

    // The audit sink URL is refused the same way, naming its bearer token; see AuditConfigurationTests.
    [Theory]
    [InlineData("SubactId:Issuer", "https://subactid:SENTINEL-URL-PASSWORD@subactid.example.test")]
    [InlineData("SubactId:UpstreamIdp:Issuer", "https://reader:SENTINEL-URL-PASSWORD@idp.example.test/realms/main")]
    [InlineData("SubactId:UpstreamIdp:MetadataUrl", "https://reader:SENTINEL-URL-PASSWORD@idp.example.test/realms/main/.well-known/openid-configuration")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:UsersUrl", "https://reader:SENTINEL-URL-PASSWORD@idp.example.test/admin/realms/main/users")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:TokenUrl", "https://SENTINEL-URL-PASSWORD@idp.example.test/realms/main/protocol/openid-connect/token")]
    [InlineData("SubactId:Ssf:Issuer", "https://reader:SENTINEL URL PASSWORD@transmitter.example.test")]
    public void No_url_setting_may_carry_credentials_and_the_error_never_repeats_them(string key, string url)
    {
        var config = With((key, url));
        if (key == "SubactId:UpstreamIdp:Issuer")
        {
            // The realm URL and the discovery URL are one setting in two forms; only one may be set.
            config.Remove("SubactId:UpstreamIdp:MetadataUrl");
        }
        else if (key == "SubactId:Ssf:Issuer")
        {
            config["SubactId:Ssf:Audience"] = "https://subactid.example.com/events";
            config["SubactId:Ssf:BearerToken"] = new string('t', 32);
        }

        var result = SubactIdOptionsLoader.Load(Build(config));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal($"{key} (environment variable {key.Replace(":", "__", StringComparison.Ordinal)}) must not carry credentials.", error);
        Assert.DoesNotContain("SENTINEL", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SubactId:Tokens:DefaultTaskTtl", "soon")]
    [InlineData("SubactId:Tokens:DefaultTaskTtl", "00:00:00")]
    [InlineData("SubactId:Tokens:DefaultTokenTtl", "-00:01:00")]
    [InlineData("SubactId:Tokens:DefaultTokenTtl", "PT0S")]
    // Months and years have no fixed length, so they cannot be a lifetime.
    [InlineData("SubactId:Tokens:DefaultTaskTtl", "P1M")]
    [InlineData("SubactId:Tokens:DefaultTaskTtl", "P1Y")]
    public void Ttls_must_be_positive_durations(string key, string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With((key, value))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains(key, error, StringComparison.Ordinal);
    }

    /// <summary>
    /// Both spellings are read, so configuration accepts the ISO 8601 durations agent registrations use.
    /// </summary>
    [Theory]
    [InlineData("00:05:00")]
    [InlineData("PT5M")]
    [InlineData("PT300S")]
    public void A_duration_may_be_a_time_span_or_an_iso_8601_duration(string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Tokens:DefaultTokenTtl", value))));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal(TimeSpan.FromMinutes(5), result.Options!.Tokens.DefaultTokenTtl);
    }

    [Fact]
    public void The_sponsor_check_mode_defaults_to_polling_the_identity_provider()
    {
        var upstream = SubactIdOptionsLoader.Load(Build(Complete)).Options!.UpstreamIdp;

        Assert.Equal(SponsorCheckMode.Poll, upstream.SponsorCheckMode);
        Assert.NotNull(upstream.SponsorCheck);
        Assert.Equal("sub", upstream.SponsorKeyClaim);
    }

    [Theory]
    [InlineData("signals")]
    [InlineData("SIGNALS")]
    public void Signals_mode_needs_none_of_the_settings_the_outbound_check_needs(string spelling)
    {
        var settings = new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorCheck:Mode"] = spelling };
        foreach (var key in SponsorCheckKeys)
        {
            settings.Remove(key);
        }

        var result = SubactIdOptionsLoader.Load(Build(settings));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal(SponsorCheckMode.Signals, result.Options!.UpstreamIdp.SponsorCheckMode);
        Assert.Null(result.Options.UpstreamIdp.SponsorCheck);
    }

    [Theory]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:UsersUrl")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:TokenUrl")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:ClientId")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:CacheTtl")]
    public void A_leftover_outbound_setting_under_signals_is_refused_rather_than_ignored(string key)
    {
        // Usually it means somebody still believes the identity provider is being asked.
        var settings = new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorCheck:Mode"] = "signals" };
        foreach (var other in SponsorCheckKeys)
        {
            settings.Remove(other);
        }

        settings[key] = key.EndsWith("ClientId", StringComparison.Ordinal) ? "subactid"
            : key.EndsWith("CacheTtl", StringComparison.Ordinal) ? "00:00:30"
            : "https://idp.example.test/somewhere";

        var result = SubactIdOptionsLoader.Load(Build(settings));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.StartsWith(key, StringComparison.Ordinal) && e.Contains("'signals'", StringComparison.Ordinal));
    }

    [Fact]
    public void An_unknown_sponsor_check_mode_is_named_rather_than_guessed_at()
    {
        var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorCheck:Mode"] = "push" }));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("must be 'poll' or 'signals'", StringComparison.Ordinal));
    }

    [Fact]
    public void The_cache_lifetime_rule_is_about_the_outbound_answer_so_signals_mode_is_not_held_to_it()
    {
        // Under poll a status may not be reused for longer than the token being issued. Under
        // signals nothing is reused, because nothing is asked.
        var settings = new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorCheck:Mode"] = "signals" };
        foreach (var key in SponsorCheckKeys)
        {
            settings.Remove(key);
        }

        Assert.True(SubactIdOptionsLoader.Load(Build(settings)).IsValid);
    }

    [Theory]
    [InlineData("oid")]
    [InlineData("preferred_username")]
    public void The_claim_a_human_is_keyed_by_can_be_named(string claim)
    {
        var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorKeyClaim"] = claim }));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Equal(claim, result.Options!.UpstreamIdp.SponsorKeyClaim);
    }

    [Theory]
    [InlineData("two words")]
    [InlineData("trailing ")]
    public void A_key_claim_that_could_never_match_is_refused(string claim)
    {
        var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorKeyClaim"] = claim }));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.StartsWith("SubactId:UpstreamIdp:SponsorKeyClaim", StringComparison.Ordinal));
    }

    [Fact]
    public void Sponsor_check_defaults_to_a_30_second_cache_and_may_not_exceed_the_token_ttl()
    {
        var defaults = SubactIdOptionsLoader.Load(Build(Complete)).Options!.UpstreamIdp.SponsorCheck!;
        Assert.Equal(TimeSpan.FromSeconds(30), defaults.CacheTtl);
        Assert.Equal("subactid", defaults.ClientId);
        Assert.Equal("https://idp.example.test/admin/realms/main/users", defaults.UsersUrl.ToString());

        var tooLong = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorCheck:CacheTtl"] = "00:06:00" }));
        Assert.False(tooLong.IsValid);
        Assert.Contains(tooLong.Errors, e => e.Contains("SponsorCheck:CacheTtl", StringComparison.Ordinal) && e.Contains("must not exceed", StringComparison.Ordinal));

        var equal = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:UpstreamIdp:SponsorCheck:CacheTtl"] = "00:05:00" }));
        Assert.True(equal.IsValid);
    }

    [Fact]
    public void The_sweeper_defaults_to_one_minute_and_batches_of_20_and_rejects_bad_values()
    {
        var defaults = SubactIdOptionsLoader.Load(Build(Complete)).Options!.Tasks;
        Assert.Equal(TimeSpan.FromMinutes(1), defaults.SweepInterval);
        Assert.Equal(20, defaults.BatchSize);

        var explicitValues = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:Tasks:SweepInterval"] = "00:00:05", ["SubactId:Tasks:SweepBatchSize"] = "7" })).Options!.Tasks;
        Assert.Equal((TimeSpan.FromSeconds(5), 7), (explicitValues.SweepInterval, explicitValues.BatchSize));

        foreach (var bad in new[] { "0", "-1", "abc", "1.5" })
        {
            var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:Tasks:SweepBatchSize"] = bad }));
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("Tasks:SweepBatchSize", StringComparison.Ordinal) && !e.Contains(bad + " ", StringComparison.Ordinal));
        }

        foreach (var interval in new[] { "00:00:00", "00:00:00.5", "2.00:00:00" })
        {
            Assert.False(SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:Tasks:SweepInterval"] = interval })).IsValid);
        }

        Assert.True(SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>(Complete) { ["SubactId:Tasks:SweepInterval"] = "1.00:00:00" })).IsValid);
    }

    [Fact]
    public void Task_retention_defaults_to_a_week_and_must_be_a_positive_duration()
    {
        Assert.Equal(TimeSpan.FromDays(7), SubactIdOptionsLoader.Load(Build(Complete)).Options!.Tasks.Retention);
        Assert.Equal(TimeSpan.FromHours(6), SubactIdOptionsLoader.Load(Build(With(("SubactId:Tasks:Retention", "PT6H")))).Options!.Tasks.Retention);

        foreach (var bad in new[] { "00:00:00", "-01:00:00", "a week" })
        {
            var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Tasks:Retention", bad))));
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("Tasks:Retention", StringComparison.Ordinal) && !e.Contains(bad, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Sign_out_retention_defaults_to_a_day_and_must_be_a_positive_duration_of_at_most_thirty_days()
    {
        Assert.Equal(TimeSpan.FromHours(24), SubactIdOptionsLoader.Load(Build(Complete)).Options!.Revocations.SignOutRetention);
        Assert.Equal(TimeSpan.FromHours(2), SubactIdOptionsLoader.Load(Build(With(("SubactId:Revocations:SignOutRetention", "PT2H")))).Options!.Revocations.SignOutRetention);
        Assert.Equal(TimeSpan.FromDays(30), SubactIdOptionsLoader.Load(Build(With(("SubactId:Revocations:SignOutRetention", "P30D")))).Options!.Revocations.SignOutRetention);

        foreach (var bad in new[] { "00:00:00", "-01:00:00", "a day", "P31D", "30.00:00:01" })
        {
            var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Revocations:SignOutRetention", bad))));
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("Revocations:SignOutRetention", StringComparison.Ordinal) && !e.Contains(bad, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Token_ttl_may_not_exceed_task_ttl()
    {
        var config = With(("SubactId:Tokens:DefaultTaskTtl", "00:05:00"), ("SubactId:Tokens:DefaultTokenTtl", "00:05:01"));

        var result = SubactIdOptionsLoader.Load(Build(config));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("SubactId:Tokens:DefaultTokenTtl", error, StringComparison.Ordinal);
        Assert.Contains("must not exceed", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Token_ttl_equal_to_task_ttl_is_allowed()
    {
        var config = With(("SubactId:Tokens:DefaultTaskTtl", "00:05:00"), ("SubactId:Tokens:DefaultTokenTtl", "00:05:00"));

        Assert.True(SubactIdOptionsLoader.Load(Build(config)).IsValid);
    }

    [Fact]
    public void Errors_never_contain_configured_values()
    {
        // Every setting is present but invalid, so every code path that could echo a value runs.
        var config = new Dictionary<string, string?>
        {
            ["SubactId:Issuer"] = "SENTINEL-ISSUER",
            ["SubactId:UpstreamIdp:MetadataUrl"] = "SENTINEL-METADATA",
            ["SubactId:UpstreamIdp:Audience"] = "   ",
            ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
            ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = "https://idp.example.test/realms/main/protocol/openid-connect/token",
            ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
            ["SubactId:Database:ConnectionString"] = "   ",
            ["SubactId:Tokens:DefaultTaskTtl"] = "SENTINEL-TASK-TTL",
            ["SubactId:Tokens:DefaultTokenTtl"] = "SENTINEL-TOKEN-TTL",
        };

        var result = SubactIdOptionsLoader.Load(Build(config));

        Assert.False(result.IsValid);
        Assert.Equal(6, result.Errors.Count);
        Assert.All(result.Errors, e => Assert.DoesNotContain("SENTINEL", e, StringComparison.Ordinal));
    }

    [Fact]
    public void Database_options_do_not_expose_the_connection_string_when_formatted()
    {
        var options = SubactIdOptionsLoader.Load(Build(Complete)).Options!;

        Assert.DoesNotContain("SENTINEL", options.Database.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("SENTINEL", $"{options.Database}", StringComparison.Ordinal);
    }

    [Fact]
    public void The_agent_bounds_default_to_the_shipped_ones_and_take_the_ttl_defaults()
    {
        var options = SubactIdOptionsLoader.Load(Build(Complete)).Options!;

        Assert.Equal(AgentRegistrationLimits.Default, options.Agents);
        Assert.Equal(options.Tokens.DefaultTaskTtl, options.Agents.DefaultTaskTtl);
        Assert.Equal(options.Tokens.DefaultTokenTtl, options.Agents.DefaultTokenTtl);
    }

    [Fact]
    public void An_operator_can_hold_every_agent_to_shorter_lifetimes()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Agents:MaxTaskTtl", "PT2H"),
            ("SubactId:Agents:MaxTokenTtl", "PT2M"),
            ("SubactId:Tokens:DefaultTaskTtl", "PT20M"),
            ("SubactId:Tokens:DefaultTokenTtl", "PT2M"))));

        Assert.True(result.IsValid);
        var limits = result.Options!.Agents;
        Assert.Equal(TimeSpan.FromHours(2), limits.MaxTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(2), limits.MaxTokenTtl);
        Assert.Equal(TimeSpan.FromMinutes(20), limits.DefaultTaskTtl);
    }

    [Fact]
    public void Agent_bounds_that_contradict_each_other_are_reported_at_startup()
    {
        // The default task lifetime is half an hour, so a ten-minute ceiling on tasks would refuse
        // every registration that names no lifetime.
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Agents:MaxTaskTtl", "PT10M"))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("SubactId:Agents:MaxTaskTtl", error, StringComparison.Ordinal);
        Assert.Contains("the default task lifetime is outside the allowed task lifetimes", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_burst_smaller_than_one_second_of_the_rate_is_refused()
    {
        // Left in, the bucket could never hold a refill, and the sustained rate would become the burst.
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:RateLimit:PermitsPerMinute", "600"), ("SubactId:RateLimit:Burst", "5"))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("SubactId:RateLimit:Burst", error, StringComparison.Ordinal);
        Assert.Contains("must be at least 10", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_burst_equal_to_one_second_of_the_rate_is_allowed()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:RateLimit:PermitsPerMinute", "600"), ("SubactId:RateLimit:Burst", "10"))));

        Assert.True(result.IsValid);
        Assert.Equal(10, result.Options!.RateLimit.Burst);
    }

    [Fact]
    public void The_rate_limit_defaults_are_consistent_with_each_other()
    {
        var limits = SubactIdOptionsLoader.Load(Build(Complete)).Options!.RateLimit;

        Assert.Equal(RateLimitOptions.DefaultPermitsPerMinute, limits.PermitsPerMinute);
        Assert.Equal(RateLimitOptions.DefaultBurst, limits.Burst);
        Assert.True(limits.Burst >= limits.PermitsPerSecond);

        Assert.Equal(RateLimitOptions.DefaultSignalPermitsPerMinute, limits.SignalPermitsPerMinute);
        Assert.Equal(RateLimitOptions.DefaultSignalBurst, limits.SignalBurst);
        Assert.True(limits.SignalBurst >= limits.SignalPermitsPerSecond);

        // The signal receivers' bucket is larger: one provider signing out every session it holds
        // must not be held to the limit sized for one agent.
        Assert.True(limits.SignalBurst > limits.Burst);
    }

    [Fact]
    public void The_scim_receiver_is_off_until_a_credential_is_configured()
    {
        Assert.Null(SubactIdOptionsLoader.Load(Build(Complete)).Options!.Scim);

        var configured = SubactIdOptionsLoader.Load(Build(With(("SubactId:Scim:BearerToken", new string('s', 32)))));
        Assert.Empty(configured.Errors);
        var scim = configured.Options!.Scim!;
        Assert.Equal((ScimSponsorKeyAttribute.ExternalId, ScimOptions.DefaultMaxUsers), (scim.SponsorKeyAttribute, scim.MaxUsers));
        Assert.Null(scim.PreviousBearerToken);
    }

    [Fact]
    public void A_scim_setting_without_a_credential_is_refused_rather_than_ignored()
    {
        // A leftover attribute choice usually means somebody expects provisioning to be received here.
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Scim:SponsorKeyAttribute", "userName"))));

        Assert.Contains(result.Errors, e => e.StartsWith("SubactId:Scim:SponsorKeyAttribute", StringComparison.Ordinal));
    }

    [Fact]
    public void A_scim_credential_is_held_to_a_length_and_the_two_must_differ()
    {
        var short_ = SubactIdOptionsLoader.Load(Build(With(("SubactId:Scim:BearerToken", "too-short"))));
        Assert.Contains(short_.Errors, e => e.StartsWith("SubactId:Scim:BearerToken", StringComparison.Ordinal));

        // Two different credentials are accepted at once.
        var same = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Scim:BearerToken", new string('s', 32)),
            ("SubactId:Scim:PreviousBearerToken", new string('s', 32)))));
        Assert.Contains(same.Errors, e => e.StartsWith("SubactId:Scim:PreviousBearerToken", StringComparison.Ordinal));

        var rotating = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Scim:BearerToken", new string('s', 32)),
            ("SubactId:Scim:PreviousBearerToken", new string('p', 32)))));
        Assert.Empty(rotating.Errors);
        Assert.NotNull(rotating.Options!.Scim!.PreviousBearerToken);
    }

    [Fact]
    public void The_scim_key_attribute_is_one_of_the_two_a_provisioning_client_sends()
    {
        var chosen = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Scim:BearerToken", new string('s', 32)),
            ("SubactId:Scim:SponsorKeyAttribute", "userName"))));
        Assert.Equal(ScimSponsorKeyAttribute.UserName, chosen.Options!.Scim!.SponsorKeyAttribute);

        var refused = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Scim:BearerToken", new string('s', 32)),
            ("SubactId:Scim:SponsorKeyAttribute", "employeeNumber"))));
        Assert.Contains(refused.Errors, e => e.StartsWith("SubactId:Scim:SponsorKeyAttribute", StringComparison.Ordinal));
    }

    [Fact]
    public void Neither_secret_is_printed_when_the_settings_are_formatted()
    {
        var scim = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Scim:BearerToken", "secret-secret-secret-secret-1234"),
            ("SubactId:Scim:PreviousBearerToken", "another-another-another-another1")))).Options!.Scim!;

        var printed = scim.ToString();

        Assert.DoesNotContain("secret-secret", printed, StringComparison.Ordinal);
        Assert.DoesNotContain("another-another", printed, StringComparison.Ordinal);
        Assert.Contains("<redacted>", printed, StringComparison.Ordinal);
    }

    [Fact]
    public void The_signals_receiver_is_off_until_a_transmitter_is_configured()
    {
        Assert.Null(SubactIdOptionsLoader.Load(Build(Complete)).Options!.Ssf);

        var configured = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Ssf:Issuer", "https://transmitter.example.test"),
            ("SubactId:Ssf:Audience", "https://subactid.example.com/events"),
            ("SubactId:Ssf:BearerToken", new string('t', 32)))));

        Assert.Empty(configured.Errors);
        var ssf = configured.Options!.Ssf!;

        // The discovery URL is derived from the issuer, as the identity provider's is.
        Assert.Equal("https://transmitter.example.test/.well-known/openid-configuration", ssf.MetadataUrl.AbsoluteUri);
        Assert.Null(ssf.PreviousBearerToken);
    }

    [Fact]
    public void A_transmitter_without_an_audience_or_a_credential_is_refused()
    {
        // Both guards or neither: without an audience any stream's event is accepted, and without a
        // credential the half of the guard that does not depend on a key is gone.
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Ssf:Issuer", "https://transmitter.example.test"))));

        Assert.Contains(result.Errors, e => e.StartsWith("SubactId:Ssf:Audience", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.StartsWith("SubactId:Ssf:BearerToken", StringComparison.Ordinal));
    }

    [Fact]
    public void A_signals_setting_without_a_transmitter_is_refused_rather_than_ignored()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Ssf:Audience", "https://subactid.example.com/events"))));

        Assert.Contains(result.Errors, e => e.StartsWith("SubactId:Ssf:Audience", StringComparison.Ordinal));
    }

    [Fact]
    public void The_two_push_credentials_must_differ_and_be_long_enough()
    {
        var same = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Ssf:Issuer", "https://transmitter.example.test"),
            ("SubactId:Ssf:Audience", "https://subactid.example.com/events"),
            ("SubactId:Ssf:BearerToken", new string('t', 32)),
            ("SubactId:Ssf:PreviousBearerToken", new string('t', 32)))));
        Assert.Contains(same.Errors, e => e.StartsWith("SubactId:Ssf:PreviousBearerToken", StringComparison.Ordinal));

        var short_ = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Ssf:Issuer", "https://transmitter.example.test"),
            ("SubactId:Ssf:Audience", "https://subactid.example.com/events"),
            ("SubactId:Ssf:BearerToken", "too-short"))));
        Assert.Contains(short_.Errors, e => e.StartsWith("SubactId:Ssf:BearerToken", StringComparison.Ordinal));
    }

    [Fact]
    public void Neither_push_credential_is_printed_when_the_settings_are_formatted()
    {
        var ssf = SubactIdOptionsLoader.Load(Build(With(
            ("SubactId:Ssf:Issuer", "https://transmitter.example.test"),
            ("SubactId:Ssf:Audience", "https://subactid.example.com/events"),
            ("SubactId:Ssf:BearerToken", "secret-secret-secret-secret-1234"),
            ("SubactId:Ssf:PreviousBearerToken", "another-another-another-another1")))).Options!.Ssf!;

        var printed = ssf.ToString();

        Assert.DoesNotContain("secret-secret", printed, StringComparison.Ordinal);
        Assert.DoesNotContain("another-another", printed, StringComparison.Ordinal);
        Assert.Contains("<redacted>", printed, StringComparison.Ordinal);
    }

    [Fact]
    public void The_signal_bucket_is_held_to_the_same_refill_rule()
    {
        var refused = SubactIdOptionsLoader.Load(Build(With(("SubactId:RateLimit:Signals:PermitsPerMinute", "6000"), ("SubactId:RateLimit:Signals:Burst", "50"))));
        Assert.Contains(refused.Errors, e => e.StartsWith("SubactId:RateLimit:Signals:Burst", StringComparison.Ordinal));

        var accepted = SubactIdOptionsLoader.Load(Build(With(("SubactId:RateLimit:Signals:PermitsPerMinute", "6000"), ("SubactId:RateLimit:Signals:Burst", "100"))));
        Assert.Empty(accepted.Errors);
        Assert.Equal((6000, 100), (accepted.Options!.RateLimit.SignalPermitsPerMinute, accepted.Options.RateLimit.SignalBurst));
    }

    private static IConfiguration Build(IEnumerable<KeyValuePair<string, string?>> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void Overload_shedding_is_on_by_default_and_sized_from_the_cores()
    {
        var overload = SubactIdOptionsLoader.Load(Build(Complete)).Options!.Overload;

        Assert.True(overload.Enabled);
        Assert.Equal(OverloadOptions.DefaultConcurrencyPerCore * Environment.ProcessorCount, overload.ConcurrencyLimit);
        Assert.Equal(overload.ConcurrencyLimit * OverloadOptions.DefaultQueueFactor, overload.QueueLimit);
        Assert.Equal(OverloadOptions.DefaultQueueTimeout, overload.QueueTimeout);
    }

    [Fact]
    public void The_overload_queue_follows_a_configured_limit_unless_it_is_set_itself()
    {
        var derived = SubactIdOptionsLoader.Load(Build(With(("SubactId:Overload:ConcurrencyLimit", "10")))).Options!.Overload;
        Assert.Equal(10, derived.ConcurrencyLimit);
        Assert.Equal(40, derived.QueueLimit);

        var set = SubactIdOptionsLoader.Load(Build(With(("SubactId:Overload:ConcurrencyLimit", "10"), ("SubactId:Overload:QueueLimit", "3"), ("SubactId:Overload:QueueTimeout", "PT0.5S")))).Options!.Overload;
        Assert.Equal(3, set.QueueLimit);
        Assert.Equal(TimeSpan.FromMilliseconds(500), set.QueueTimeout);
    }

    [Theory]
    [InlineData("SubactId:Overload:ConcurrencyLimit", "0")]
    [InlineData("SubactId:Overload:ConcurrencyLimit", "100001")]
    [InlineData("SubactId:Overload:ConcurrencyLimit", "2147483647")]
    [InlineData("SubactId:Overload:QueueLimit", "-1")]
    [InlineData("SubactId:Overload:QueueLimit", "1000001")]
    [InlineData("SubactId:Overload:QueueTimeout", "PT0S")]
    [InlineData("SubactId:Overload:QueueTimeout", "PT31S")]
    [InlineData("SubactId:Overload:Enabled", "sometimes")]
    public void An_overload_setting_outside_its_range_is_refused_by_name(string key, string value)
    {
        var result = SubactIdOptionsLoader.Load(Build(With((key, value))));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.StartsWith(key, StringComparison.Ordinal));
    }

    [Fact]
    public void An_overload_queue_of_zero_means_none_waits()
    {
        var overload = SubactIdOptionsLoader.Load(Build(With(("SubactId:Overload:QueueLimit", "0")))).Options!.Overload;

        Assert.Equal(0, overload.QueueLimit);
    }

    [Fact]
    public void The_largest_concurrency_limit_still_derives_a_queue_that_fits()
    {
        // Derived as four times the limit. At the largest accepted limit that must still be a number
        // the limiter takes, not an overflow at startup.
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:Overload:ConcurrencyLimit", OverloadOptions.MaxConcurrencyLimit.ToString(System.Globalization.CultureInfo.InvariantCulture)))));

        Assert.True(result.IsValid);
        Assert.InRange(result.Options!.Overload.QueueLimit, 0, OverloadOptions.MaxQueueLimit);
    }

    [Fact]
    public void Overload_shedding_can_be_switched_off()
    {
        Assert.False(SubactIdOptionsLoader.Load(Build(With(("SubactId:Overload:Enabled", "false")))).Options!.Overload.Enabled);
    }

    [Fact]
    public void Subject_token_types_default_to_empty()
    {
        var options = SubactIdOptionsLoader.Load(Build(Complete)).Options!;

        Assert.Empty(options.UpstreamIdp.SubjectTokenTypes);
    }

    [Fact]
    public void Subject_token_types_are_read_as_a_trimmed_comma_separated_list()
    {
        var options = SubactIdOptionsLoader.Load(Build(With(("SubactId:UpstreamIdp:SubjectTokenTypes", "at+jwt, application/at+jwt")))).Options!;

        Assert.Equal(["at+jwt", "application/at+jwt"], options.UpstreamIdp.SubjectTokenTypes);
    }

    [Theory]
    [InlineData("SubactId:UpstreamIdp:SubjectTokenTypes:0")]
    [InlineData("SubactId:UpstreamIdp:SubjectTokenTypes:1")]
    public void Subject_token_types_given_as_a_numbered_list_are_refused_rather_than_ignored(string key)
    {
        // What a JSON array or a SubactId__UpstreamIdp__SubjectTokenTypes__0 variable produces. Read
        // as unset, the list would accept every type while the operator believes it narrows them.
        var result = SubactIdOptionsLoader.Load(Build(With((key, "at+jwt"))));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Contains("SubjectTokenTypes", StringComparison.Ordinal));
        Assert.StartsWith("SubactId:UpstreamIdp:SubjectTokenTypes (environment variable SubactId__UpstreamIdp__SubjectTokenTypes) must be one comma-separated value", error, StringComparison.Ordinal);
        Assert.DoesNotContain("at+jwt", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Blocking_private_networks_for_key_fetch_defaults_to_false()
    {
        var options = SubactIdOptionsLoader.Load(Build(Complete)).Options!;

        Assert.False(options.AgentKeys.BlockPrivateNetworks);
    }

    [Fact]
    public void Blocking_private_networks_for_key_fetch_can_be_enabled()
    {
        var options = SubactIdOptionsLoader.Load(Build(With(("SubactId:AgentKeys:BlockPrivateNetworks", "true")))).Options!;

        Assert.True(options.AgentKeys.BlockPrivateNetworks);
    }

    [Fact]
    public void A_non_boolean_block_private_networks_setting_is_rejected()
    {
        var result = SubactIdOptionsLoader.Load(Build(With(("SubactId:AgentKeys:BlockPrivateNetworks", "yes"))));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("AgentKeys:BlockPrivateNetworks", StringComparison.Ordinal));
    }

    private static Dictionary<string, string?> With(params (string Key, string Value)[] overrides)
    {
        var config = new Dictionary<string, string?>(Complete);
        foreach (var (key, value) in overrides)
        {
            config[key] = value;
        }

        return config;
    }
}
