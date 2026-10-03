using System.Buffers.Text;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace SubactId.Conformance;

/// <summary>
/// The twenty adversarial cases, run against a live instance through its public surface only.
/// Each test guards one server check and names it; remove that check and the test fails. Every
/// refusal is also checked against the audit ledger, because a denial that is not recorded is
/// a denial that did not happen as far as the person it protects is concerned.
/// </summary>
[Collection(LiveInstanceCollection.Name)]
public sealed class ConformanceTests(LiveInstance subactid)
{
    private const string Jira = "https://jira.internal";
    private const string Confluence = "https://confluence.internal";
    private const string Db = "https://db.internal";

    /// <summary>1. Delegation, not impersonation: <c>sub</c> is the human, the agent is only ever in <c>act</c>, and a subject that is an agent is refused.</summary>
    [Fact]
    public async Task The_subject_is_always_the_human_and_the_agent_is_only_ever_the_actor()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();

        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);
        var claims = subactid.VerifiedClaims(token.GetProperty("access_token").GetString()!);

        Assert.Equal(human, claims.GetProperty("sub").GetString());
        Assert.Equal("agent:" + agent.AgentId, claims.GetProperty("act").GetProperty("sub").GetString());
        Assert.Equal(1, claims.GetProperty("act").GetProperty("depth").GetInt32());
        Assert.Equal("agent:" + agent.AgentId, claims.GetProperty("client_id").GetString());
        Assert.Equal(human, claims.GetProperty("task").GetProperty("sponsor").GetString());
        Assert.Equal(subactid.Issuer, claims.GetProperty("iss").GetString());

        var introspection = await subactid.IntrospectAsync(token.GetProperty("access_token").GetString()!);
        Assert.True(introspection.GetProperty("active").GetBoolean());
        Assert.Equal(human, introspection.GetProperty("sub").GetString());
        Assert.Equal("agent:" + agent.AgentId, introspection.GetProperty("act").GetProperty("sub").GetString());

        // An agent cannot be the subject: a subject token naming an agent is refused, not turned into a token an agent acts for.
        using var impersonation = await subactid.ExchangeAsync(agent, subactid.SubjectToken("agent:" + agent.AgentId));
        await LiveInstance.AssertOAuthErrorAsync(impersonation, HttpStatusCode.BadRequest, "invalid_grant");
        await AssertDeniedAsync(agent, since, "subject_is_agent");
    }

    /// <summary>2. Effective scope is the intersection of user, agent and request at exchange; nothing outside it is ever issued, and an empty intersection is an error, not an empty token.</summary>
    [Fact]
    public async Task Scope_at_exchange_is_the_intersection_and_never_wider()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync(allowedScopes: ["jira:read", "jira:comment"]);
        var human = subactid.NewHuman();

        // User may jira:read and jira:admin; agent may jira:read and jira:comment; asked for all three.
        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, scope: "openid jira:read jira:admin"), scope: "jira:read jira:comment jira:admin");
        var token = await LiveInstance.TokenAsync(response);
        Assert.Equal("jira:read", token.GetProperty("scope").GetString());
        Assert.Equal("jira:read", subactid.VerifiedClaims(token.GetProperty("access_token").GetString()!).GetProperty("scope").GetString());

        using var empty = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, scope: "openid jira:read"), scope: "jira:admin");
        await LiveInstance.AssertOAuthErrorAsync(empty, HttpStatusCode.BadRequest, "invalid_scope");
        await AssertDeniedAsync(agent, since, "scope_intersection_empty");

        using var outsideAgent = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, scope: "openid confluence:read"), scope: "confluence:read");
        await LiveInstance.AssertOAuthErrorAsync(outsideAgent, HttpStatusCode.BadRequest, "invalid_scope");
        Assert.Equal(2, (await subactid.DenialsAsync(agent, since)).Count(d => d.GetProperty("reason").GetString() == "scope_intersection_empty"));
    }

    /// <summary>3. Scope only narrows on refresh: a scope the task was not granted is refused even when the user and the agent would both allow it.</summary>
    [Fact]
    public async Task Scope_only_narrows_on_refresh()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync(allowedScopes: ["jira:read", "jira:comment"]);
        var human = subactid.NewHuman();

        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, scope: "openid jira:read jira:comment"), scope: "jira:read");
        var token = await LiveInstance.TokenAsync(response);
        Assert.Equal("jira:read", token.GetProperty("scope").GetString());
        var grant = token.GetProperty("refresh_token").GetString()!;

        // Both the user and the agent allow jira:comment; the task does not, and the task is what the grant is for.
        using var widened = await subactid.RefreshAsync(agent, grant, scope: "jira:read jira:comment");
        await LiveInstance.AssertOAuthErrorAsync(widened, HttpStatusCode.BadRequest, "invalid_scope");
        await AssertDeniedAsync(agent, since, "scope_widened");

        using var same = await subactid.RefreshAsync(agent, grant, scope: "jira:read");
        var refreshed = await LiveInstance.TokenAsync(same);
        Assert.Equal("jira:read", refreshed.GetProperty("scope").GetString());
        Assert.Equal(token.GetProperty("task_id").GetString(), refreshed.GetProperty("task_id").GetString());
        Assert.NotEqual(subactid.VerifiedClaims(token.GetProperty("access_token").GetString()!).GetProperty("jti").GetString(), subactid.VerifiedClaims(refreshed.GetProperty("access_token").GetString()!).GetProperty("jti").GetString());
    }

    /// <summary>4. The audience must be one the agent is allowed, the token is bound to it, and a refresh cannot move the task to another one.</summary>
    [Fact]
    public async Task The_audience_must_be_allowed_and_a_task_is_bound_to_it()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync(allowedAudiences: [Jira, Confluence]);
        var human = subactid.NewHuman();

        using var forbidden = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), resource: Db);
        await LiveInstance.AssertOAuthErrorAsync(forbidden, HttpStatusCode.BadRequest, "invalid_target");
        await AssertDeniedAsync(agent, since, "audience_not_allowed");

        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), resource: Jira);
        var token = await LiveInstance.TokenAsync(response);
        Assert.Equal(Jira, subactid.VerifiedClaims(token.GetProperty("access_token").GetString()!).GetProperty("aud").GetString());

        // Confluence is allowed for the agent, but this task is a Jira task.
        using var moved = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!, resource: Confluence);
        await LiveInstance.AssertOAuthErrorAsync(moved, HttpStatusCode.BadRequest, "invalid_target");
        await AssertDeniedAsync(agent, since, "audience_mismatch");
    }

    /// <summary>5. A token never outlives its task: at issue and at refresh, <c>exp</c> is bounded by the task's expiry, not only by <c>max_token_ttl</c>.</summary>
    [Fact]
    public async Task A_token_never_outlives_its_task()
    {
        var agent = await subactid.RegisterAgentAsync(maxTaskTtl: "PT1M", maxTokenTtl: "PT1M");
        var human = subactid.NewHuman();

        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);
        var claims = subactid.VerifiedClaims(token.GetProperty("access_token").GetString()!);
        var taskExpiry = DateTimeOffset.Parse(token.GetProperty("task_expires_at").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
        Assert.InRange(token.GetProperty("expires_in").GetInt64(), 1, 60);
        Assert.True(claims.GetProperty("exp").GetInt64() <= claims.GetProperty("task").GetProperty("exp").GetInt64(), "The token's exp is past its task's exp.");
        Assert.True(claims.GetProperty("exp").GetInt64() <= taskExpiry.ToUnixTimeSeconds(), "The token's exp is past task_expires_at.");

        // Well into the task: a fresh token is cut to what is left, not given a full token lifetime.
        await Task.Delay(TimeSpan.FromSeconds(20));
        // Measured before the request goes out. Measuring after it returns would subtract the
        // round trip from the budget the instance was working with, and a slow answer would fail
        // a check the instance passed.
        var remaining = (taskExpiry - DateTimeOffset.UtcNow).TotalSeconds;
        using var refresh = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!);
        var refreshed = await LiveInstance.TokenAsync(refresh);
        Assert.InRange(refreshed.GetProperty("expires_in").GetInt64(), 1, (long)Math.Ceiling(remaining) + 1);
        Assert.True(subactid.VerifiedClaims(refreshed.GetProperty("access_token").GetString()!).GetProperty("exp").GetInt64() <= taskExpiry.ToUnixTimeSeconds(), "The refreshed token's exp is past its task's expiry.");
    }

    /// <summary>6. A client assertion is accepted once, from the registered key, for a registered agent: a replay, a forged signature and an unknown agent are all <c>invalid_client</c>.</summary>
    [Fact]
    public async Task A_client_assertion_is_accepted_once_and_only_from_the_registered_key()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();
        var assertion = subactid.ClientAssertion(agent);

        using var first = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), actorToken: assertion);
        await LiveInstance.TokenAsync(first);

        using var replay = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), actorToken: assertion);
        await LiveInstance.AssertOAuthErrorAsync(replay, HttpStatusCode.Unauthorized, "invalid_client");
        await AssertDeniedAsync(null, since, "actor_replayed");

        using var forgedKey = RSA.Create(2048);
        using var forged = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), actorToken: subactid.ClientAssertion(agent, key: forgedKey));
        await LiveInstance.AssertOAuthErrorAsync(forged, HttpStatusCode.Unauthorized, "invalid_client");
        await AssertDeniedAsync(null, since, "actor_invalid_signature");

        var unknown = new ConformanceAgent($"conformance-unknown-{Guid.NewGuid():N}"[..40], forgedKey);
        using var stranger = await subactid.ExchangeAsync(unknown, subactid.SubjectToken(human));
        await LiveInstance.AssertOAuthErrorAsync(stranger, HttpStatusCode.Unauthorized, "invalid_client");
        await AssertDeniedAsync(null, since, "actor_unknown_agent");
    }

    /// <summary>7. Revocation and disabling take effect at once: a killed task refuses refresh and introspects as revoked; a disabled agent gets nothing new and its live tokens introspect as inactive.</summary>
    [Fact]
    public async Task Revocation_and_disabling_take_effect_at_once()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();

        // Operator kill switch on the task.
        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);
        var accessToken = token.GetProperty("access_token").GetString()!;
        var taskId = token.GetProperty("task_id").GetString()!;
        using var killed = await subactid.Admin.DeleteAsync($"/admin/tasks/{Uri.EscapeDataString(taskId)}");
        Assert.Equal(HttpStatusCode.OK, killed.StatusCode);

        using var refresh = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!);
        await LiveInstance.AssertOAuthErrorAsync(refresh, HttpStatusCode.BadRequest, "access_denied");
        await AssertDeniedAsync(agent, since, "task_revoked");
        var revoked = await subactid.IntrospectAsync(accessToken);
        Assert.False(revoked.GetProperty("active").GetBoolean());
        Assert.Equal("operator_kill_switch", revoked.GetProperty("revocation_reason").GetString());
        Assert.True(revoked.TryGetProperty("revoked_at", out _));

        // The agent revokes its own grant: the task dies with it.
        using var second = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var secondToken = await LiveInstance.TokenAsync(second);
        using var revocation = await subactid.RevokeAsync(agent, secondToken.GetProperty("refresh_token").GetString()!);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);
        using var refreshRevoked = await subactid.RefreshAsync(agent, secondToken.GetProperty("refresh_token").GetString()!);
        await LiveInstance.AssertOAuthErrorAsync(refreshRevoked, HttpStatusCode.BadRequest, "access_denied");
        Assert.Equal(2, (await subactid.DenialsAsync(agent, since)).Count(d => d.GetProperty("reason").GetString() == "task_revoked"));
        Assert.False((await subactid.IntrospectAsync(secondToken.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());

        // Disabling the agent: nothing new, and what it holds is no longer active.
        using var third = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var thirdToken = await LiveInstance.TokenAsync(third);
        using var disabled = await subactid.Admin.PatchAsync($"/admin/agents/{Uri.EscapeDataString(agent.AgentId)}", new StringContent("{\"enabled\": false}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);

        // A disabled agent is refused only after its key has proved the assertion, so the denial
        // names it; counted across the ledger anyway, so the check does not depend on which.
        var disabledBefore = (await subactid.DenialsAsync(null, since)).Count(d => d.GetProperty("reason").GetString() == "agent_disabled");
        using var exchangeDisabled = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.AssertOAuthErrorAsync(exchangeDisabled, HttpStatusCode.BadRequest, "access_denied");
        using var refreshDisabled = await subactid.RefreshAsync(agent, thirdToken.GetProperty("refresh_token").GetString()!);
        await LiveInstance.AssertOAuthErrorAsync(refreshDisabled, HttpStatusCode.BadRequest, "access_denied");
        Assert.Equal(disabledBefore + 2, (await subactid.DenialsAsync(null, since)).Count(d => d.GetProperty("reason").GetString() == "agent_disabled"));
        var inactive = await subactid.IntrospectAsync(thirdToken.GetProperty("access_token").GetString()!);
        Assert.False(inactive.GetProperty("active").GetBoolean());
        Assert.Equal("agent_disabled", inactive.GetProperty("revocation_reason").GetString());
    }

    /// <summary>8. A subject token is trusted only from the identity provider, only for this audience, and only while valid: expired, foreign-signed, wrong audience and wrong issuer are all <c>invalid_grant</c>, each recorded.</summary>
    [Fact]
    public async Task A_subject_token_is_trusted_only_from_the_identity_provider_and_only_while_valid()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();
        var now = DateTimeOffset.UtcNow;

        using var expired = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, overrides: [("exp", now.AddMinutes(-5).ToUnixTimeSeconds()), ("iat", now.AddMinutes(-10).ToUnixTimeSeconds())]));
        await LiveInstance.AssertOAuthErrorAsync(expired, HttpStatusCode.BadRequest, "invalid_grant");
        await AssertDeniedAsync(agent, since, "subject_expired");

        // Signed by a key the identity provider never published, under the provider's own kid.
        using var foreignKey = RSA.Create(2048);
        using var forged = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, key: foreignKey));
        await LiveInstance.AssertOAuthErrorAsync(forged, HttpStatusCode.BadRequest, "invalid_grant");

        using var wrongAudience = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, overrides: [("aud", "someone-else")]));
        await LiveInstance.AssertOAuthErrorAsync(wrongAudience, HttpStatusCode.BadRequest, "invalid_grant");

        using var wrongIssuer = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, overrides: [("iss", "https://idp.attacker.example")]));
        await LiveInstance.AssertOAuthErrorAsync(wrongIssuer, HttpStatusCode.BadRequest, "invalid_grant");

        var denials = await subactid.DenialsAsync(agent, since);
        Assert.True(denials.Count >= 4, $"Expected a denial record per refused subject token, found {denials.Count}.");
        Assert.All(denials, d => Assert.StartsWith("subject_", d.GetProperty("reason").GetString(), StringComparison.Ordinal));
        Assert.All(denials, d => Assert.Equal("deny", d.GetProperty("decision").GetString()));

        // And the same token, properly issued, is accepted: the refusals above were the checks, not the setup.
        using var accepted = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.TokenAsync(accepted);
    }

    /// <summary>9. The human is re-checked at the identity provider on every refresh: disabling or deleting them there ends every task they sponsor within one token lifetime, and an identity provider that cannot answer is never read as a yes.</summary>
    [Fact]
    public async Task A_task_dies_with_the_human_it_acts_for()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();

        // An active human, renewing normally, so what follows is the check and not the setup.
        // A different person for each case on purpose: the instance may reuse a sponsor's status
        // for as long as the token it is issuing, so asking about one before changing them would
        // be answered from that and prove nothing.
        var active = subactid.NewHuman();
        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(active));
        var token = await LiveInstance.TokenAsync(response);
        using var renewed = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!);
        await LiveInstance.TokenAsync(renewed);

        // Disabled at the identity provider. The task is untouched here and the agent is still
        // enabled: the only thing that changed is the person, and that is enough.
        var suspended = subactid.NewHuman();
        using var forSuspended = await subactid.ExchangeAsync(agent, subactid.SubjectToken(suspended));
        var suspendedToken = await LiveInstance.TokenAsync(forSuspended);
        var grant = suspendedToken.GetProperty("refresh_token").GetString()!;
        subactid.SetSponsorEnabled(suspended, enabled: false);
        using var disabled = await subactid.RefreshAsync(agent, grant);
        await LiveInstance.AssertOAuthErrorAsync(disabled, HttpStatusCode.BadRequest, "access_denied", grant);
        await AssertDeniedAsync(agent, since, "sponsor_disabled");

        // Deleted outright is not "not disabled": an answer the identity provider does not have
        // is not an answer that the person is fine.
        var removed = subactid.NewHuman();
        using var forRemoved = await subactid.ExchangeAsync(agent, subactid.SubjectToken(removed));
        var removedToken = await LiveInstance.TokenAsync(forRemoved);
        subactid.DeleteSponsor(removed);
        using var deleted = await subactid.RefreshAsync(agent, removedToken.GetProperty("refresh_token").GetString()!);
        await LiveInstance.AssertOAuthErrorAsync(deleted, HttpStatusCode.BadRequest, "access_denied");
        await AssertDeniedAsync(agent, since, "sponsor_not_found");
    }

    /// <summary>10. The ledger is sealed: every record is provably inside a signed checkpoint, so a record removed, altered or inserted between two others cannot go unnoticed.</summary>
    /// <remarks>
    /// End to end through the public surface, and with no help from the server's own code: the
    /// record's leaf is rebuilt here from what was published, the audit path is folded here, the
    /// checkpoint's signed bytes are rebuilt here from the fields it was published with, and the
    /// signature is checked against the JWKS anyone can fetch. A control plane that published a
    /// root nothing hashes to, or a signature made by a key it does not publish, fails this.
    /// </remarks>
    [Fact]
    public async Task The_audit_ledger_is_sealed_and_every_record_proves_itself()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();

        // Something to seal: an allow, a denial, and a refresh, all under one agent.
        using var issued = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(issued);
        using var refused = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), resource: Db);
        await LiveInstance.AssertOAuthErrorAsync(refused, HttpStatusCode.BadRequest, "invalid_target");
        using var refreshed = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!);
        await LiveInstance.TokenAsync(refreshed);

        // A record is written in the transaction that made the decision and sealed a window later,
        // so the ledger answers at once and the seal follows. Both halves are checked: the records
        // are there now, and they are inside a signed root before the window is out.
        var records = await subactid.LedgerAsync(since);
        Assert.True(records.Count >= 3, $"Expected the exchange, the denial and the refresh in the ledger, found {records.Count} records.");
        Assert.All(records, r => Assert.True(r.TryGetProperty("checkpoint", out _), "A published record does not say which checkpoint seals it."));

        records = await SealedAsync(since, records.Count);

        var checkpoints = await CheckpointsAsync();
        var discovery = await DiscoveryAsync();
        var jwks = await subactid.Http.GetFromJsonAsync<JsonElement>(new Uri(discovery.GetProperty("jwks_uri").GetString()!));

        // Every checkpoint is signed by a key the instance publishes, and each links to the one
        // before it by the hash of that one's signed bytes. A checkpoint removed or replaced
        // breaks the link at the one that follows.
        byte[]? previous = null;
        foreach (var checkpoint in checkpoints)
        {
            var signed = SignedBytes(checkpoint);
            Assert.True(
                VerifyEs256(signed, FromHex(checkpoint.GetProperty("signature").GetString()!), checkpoint.GetProperty("kid").GetString()!, jwks),
                $"Checkpoint {checkpoint.GetProperty("checkpoint_id").GetInt64()} is not signed by a key the instance publishes.");

            var link = checkpoint.GetProperty("prev_checkpoint_hash");
            if (previous is null)
            {
                Assert.Equal(JsonValueKind.Null, link.ValueKind);
            }
            else
            {
                Assert.Equal(ToHex(SHA256.HashData(previous)), link.GetString());
            }

            previous = signed;
        }

        // And every record proves itself into the root its checkpoint signed, from the record as
        // it was published and nothing else.
        var byId = checkpoints.ToDictionary(c => c.GetProperty("checkpoint_id").GetInt64());
        foreach (var record in records)
        {
            var seq = record.GetProperty("seq").GetInt64();
            var checkpoint = byId[record.GetProperty("checkpoint").GetInt64()];
            using var response = await subactid.Admin.GetAsync(new Uri($"/audit/records/{seq}/proof", UriKind.Relative));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var proof = await response.Content.ReadFromJsonAsync<JsonElement>();

            Assert.Equal(seq, proof.GetProperty("seq").GetInt64());
            Assert.Equal(
                checkpoint.GetProperty("root_hash").GetString(),
                proof.GetProperty("checkpoint").GetProperty("root_hash").GetString());

            byte[] leafInput = [LeafPrefix, .. CanonicalJson(record)];
            var leaf = SHA256.HashData(leafInput);
            var path = proof.GetProperty("audit_path").EnumerateArray().Select(step => FromHex(step.GetString()!)).ToList();
            var root = FoldPath(leaf, proof.GetProperty("leaf_index").GetInt64(), checkpoint.GetProperty("tree_size").GetInt64(), path);

            Assert.Equal(checkpoint.GetProperty("root_hash").GetString(), ToHex(root));
        }

        // A sequence number nothing was ever written at has no proof, however plausible it looks.
        using var absent = await subactid.Admin.GetAsync(new Uri($"/audit/records/{records.Max(r => r.GetProperty("seq").GetInt64()) + 1_000_000}/proof", UriKind.Relative));
        Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);

        // Hashes are lowercase hex, and a record that is not a summary carries no count.
        Assert.All(checkpoints, c => Assert.Matches("^[0-9a-f]{64}$", c.GetProperty("root_hash").GetString()));
        Assert.All(records, r => Assert.False(r.TryGetProperty("count", out _) && r.GetProperty("decision").GetString() == "allow", "An allowed record carries a count, which only a summary may."));
    }

    /// <summary>11. A high-risk audience is marked in the token itself: the operator states it once on the registration and every token for that audience tells the tool server to introspect.</summary>
    [Fact]
    public async Task A_token_for_a_high_risk_audience_says_so_itself()
    {
        var agent = await subactid.RegisterAgentAsync(allowedAudiences: [Jira, Db], highRiskAudiences: [Db], allowedScopes: ["jira:read", "jira:comment"]);
        var human = subactid.NewHuman();

        using var highRisk = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), resource: Db);
        var token = await LiveInstance.TokenAsync(highRisk);
        var claims = subactid.VerifiedClaims(token.GetProperty("access_token").GetString()!);
        Assert.True(claims.GetProperty("introspect_required").GetBoolean());

        // And an ordinary audience is exactly what it always was: the claim is absent, not false.
        using var ordinary = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human), resource: Jira);
        var ordinaryToken = await LiveInstance.TokenAsync(ordinary);
        Assert.False(subactid.VerifiedClaims(ordinaryToken.GetProperty("access_token").GetString()!).TryGetProperty("introspect_required", out _));
    }

    /// <summary>12. A refusal never quotes the credential back: no subject token, client assertion or task grant appears in an error the endpoint returns.</summary>
    [Fact]
    public async Task No_refusal_hands_back_the_credential_it_refused()
    {
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();
        var subjectToken = subactid.SubjectToken(human, overrides: [("aud", "someone-else")]);
        var assertion = subactid.ClientAssertion(agent);

        using var badSubject = await subactid.ExchangeAsync(agent, subjectToken, actorToken: assertion);
        await LiveInstance.AssertOAuthErrorAsync(badSubject, HttpStatusCode.BadRequest, "invalid_grant", subjectToken, assertion);

        // A grant that does not exist: the value must not come back either, whole or in part.
        var stranger = "task_grant_" + Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        using var unknownGrant = await subactid.RefreshAsync(agent, stranger);
        await LiveInstance.AssertOAuthErrorAsync(unknownGrant, HttpStatusCode.BadRequest, "invalid_grant", stranger);

        // And a request that fails validation outright, where the endpoint is quoting fields back.
        using var oversized = await subactid.ExchangeAsync(agent, new string('a', 20_000));
        var body = await oversized.Content.ReadAsStringAsync();
        LiveInstance.AssertNoSecretIn(body, new string('a', 20_000));
    }

    /// <summary>
    /// 13. A human this control plane will not act for is refused whatever the identity provider
    /// says about them: what was running ends, the task cannot be renewed, and a subject token
    /// that is still perfectly valid cannot start another.
    /// </summary>
    /// <remarks>
    /// The companion to case 9, and the one that holds in either mode. Case 9 disables somebody
    /// at the identity provider, which an instance that does not poll one never learns; this
    /// refuses them here, which is the only lever that works in both. The identity provider is
    /// left saying the person is perfectly fine throughout, so a control plane that answered from
    /// it rather than from its own decision would fail this.
    /// </remarks>
    [Fact]
    public async Task A_human_the_control_plane_will_not_act_for_is_refused_whatever_the_identity_provider_says()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();

        // Running normally, and enabled at the identity provider, so what follows is the check
        // and not the setup.
        var human = subactid.NewHuman();
        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);
        var accessToken = token.GetProperty("access_token").GetString()!;
        var grant = token.GetProperty("refresh_token").GetString()!;

        // Refused here rather than there. Nothing about the person changes at the identity
        // provider: it still has them enabled, and is never told otherwise.
        await subactid.BlockSponsorAsync(human);

        // What was already running is over, which is what separates this from a refusal that
        // only takes effect at the next renewal.
        Assert.False((await subactid.IntrospectAsync(accessToken)).GetProperty("active").GetBoolean());

        // The task cannot be renewed.
        using var refreshed = await subactid.RefreshAsync(agent, grant);
        await LiveInstance.AssertOAuthErrorAsync(refreshed, HttpStatusCode.BadRequest, "access_denied", grant);

        // And a subject token that is still valid, for a person the identity provider is still
        // happy with, cannot open a new task either.
        var stillValid = subactid.SubjectToken(human);
        using var again = await subactid.ExchangeAsync(agent, stillValid);
        await LiveInstance.AssertOAuthErrorAsync(again, HttpStatusCode.BadRequest, "access_denied", stillValid);

        await AssertDeniedAsync(agent, since, "sponsor_disabled");

        // Somebody else is untouched: this is a refusal about one person, not a mode the control
        // plane fell into.
        var bystander = subactid.NewHuman();
        using var unaffected = await subactid.ExchangeAsync(agent, subactid.SubjectToken(bystander));
        await LiveInstance.TokenAsync(unaffected);
    }

    /// <summary>RFC 6962's leaf prefix: what stops an interior node being presented as a leaf.</summary>
    private const byte LeafPrefix = 0x00;

    /// <summary>RFC 6962's node prefix.</summary>
    private const byte NodePrefix = 0x01;

    /// <summary>
    /// Longest the suite waits for the sealing pass. The instance under test runs with a short
    /// checkpoint interval, so this is many windows; a longer default would still be sealed, only
    /// later, and the suite would be waiting rather than testing.
    /// </summary>
    private static readonly TimeSpan SealDeadline = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The records since <paramref name="since"/>, once every one of them is inside a checkpoint.
    /// A record is written at once and sealed a window later, so this is the window passing, not
    /// the record arriving: they are all there before the first poll.
    /// </summary>
    private async Task<IReadOnlyList<JsonElement>> SealedAsync(DateTimeOffset since, int expected)
    {
        var deadline = DateTime.UtcNow + SealDeadline;
        while (true)
        {
            var records = await subactid.LedgerAsync(since);
            var unsealed = records.Count(r => r.GetProperty("checkpoint").ValueKind == JsonValueKind.Null);
            if (records.Count >= expected && unsealed == 0)
            {
                return records;
            }

            Assert.True(
                DateTime.UtcNow < deadline,
                $"{unsealed} of {records.Count} record(s) were still unsealed after {SealDeadline}. The sealing pass is not running, or SubactId:Audit:Checkpoint:Interval is longer than the suite waits.");

            await Task.Delay(TimeSpan.FromSeconds(1));
        }
    }

    /// <summary>Every published checkpoint, oldest first, following the pages.</summary>
    private async Task<IReadOnlyList<JsonElement>> CheckpointsAsync()
    {
        var checkpoints = new List<JsonElement>();
        long? after = null;
        do
        {
            var query = after is null ? "/audit/checkpoints?limit=100" : $"/audit/checkpoints?limit=100&after={after}";
            using var response = await subactid.Admin.GetAsync(new Uri(query, UriKind.Relative));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var page = await response.Content.ReadFromJsonAsync<JsonElement>();
            checkpoints.AddRange(page.GetProperty("checkpoints").EnumerateArray().Select(c => c.Clone()));
            var next = page.GetProperty("next_after");
            after = next.ValueKind == JsonValueKind.Null ? null : next.GetInt64();
        }
        while (after is not null);

        Assert.NotEmpty(checkpoints);
        return checkpoints;
    }

    /// <summary>
    /// The canonical JSON of a published record, rebuilt here from spec section 7: the semantic
    /// fields with keys in lexicographic order, no whitespace, nulls written explicitly, and
    /// <c>count</c> present only on a summary. <c>seq</c> and <c>checkpoint</c> are not inside it,
    /// because neither is a fact about the event.
    /// </summary>
    private static byte[] CanonicalJson(JsonElement record)
    {
        string[] fields = ["agent_id", "audience", "count", "decision", "delegation_depth", "event", "jti", "reason", "scope", "sponsor", "task_id", "ts"];
        return Canonical(record, fields);
    }

    /// <summary>The bytes a checkpoint's signature was taken over: its published fields, minus the signature.</summary>
    private static byte[] SignedBytes(JsonElement checkpoint)
    {
        string[] fields = ["checkpoint_id", "closed_at", "first_seq", "kid", "last_seq", "prev_checkpoint_hash", "root_hash", "tree_size"];
        return Canonical(checkpoint, fields);
    }

    private static byte[] Canonical(JsonElement value, string[] fields)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            writer.WriteStartObject();
            foreach (var field in fields)
            {
                if (!value.TryGetProperty(field, out var member))
                {
                    // Only count may be absent, and only on a record that stands for one event.
                    Assert.Equal("count", field);
                    continue;
                }

                writer.WritePropertyName(field);
                member.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// The root an audit path implies, folded here rather than taken from the server: RFC 6962
    /// section 2.1.1, over the leaf at <paramref name="index"/> of a tree of
    /// <paramref name="treeSize"/> leaves.
    /// </summary>
    private static byte[] FoldPath(byte[] leaf, long index, long treeSize, IReadOnlyList<byte[]> path)
    {
        Assert.InRange(index, 0L, treeSize - 1);

        var fn = index;
        var sn = treeSize - 1;
        var root = leaf;
        foreach (var sibling in path)
        {
            Assert.NotEqual(0L, sn);
            if ((fn & 1) == 1 || fn == sn)
            {
                byte[] joined = [NodePrefix, .. sibling, .. root];
                root = SHA256.HashData(joined);
                while (fn != 0 && (fn & 1) == 0)
                {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
            else
            {
                byte[] joined = [NodePrefix, .. root, .. sibling];
                root = SHA256.HashData(joined);
            }

            fn >>= 1;
            sn >>= 1;
        }

        Assert.Equal(0L, sn);
        return root;
    }

    /// <summary>Whether <paramref name="signature"/> is an ES256 signature over <paramref name="signed"/> by the published key <paramref name="kid"/>.</summary>
    private static bool VerifyEs256(byte[] signed, byte[] signature, string kid, JsonElement jwks)
    {
        foreach (var jwk in jwks.GetProperty("keys").EnumerateArray())
        {
            if (jwk.GetProperty("kid").GetString() != kid || jwk.GetProperty("kty").GetString() != "EC" || jwk.GetProperty("crv").GetString() != "P-256")
            {
                continue;
            }

            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = Base64Url.DecodeFromChars(jwk.GetProperty("x").GetString()!),
                    Y = Base64Url.DecodeFromChars(jwk.GetProperty("y").GetString()!),
                },
            });

            return key.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        return false;
    }

    /// <summary>14. Discovery advertises what the control plane does and nothing else: <c>private_key_jwt</c> at the token and revocation endpoints, the assertion algorithms it verifies, and no OpenID Provider claims.</summary>
    [Fact]
    public async Task Discovery_advertises_only_what_the_control_plane_does()
    {
        var document = await DiscoveryAsync();

        string[] List(string member) => document.GetProperty(member).EnumerateArray().Select(e => e.GetString()!).ToArray();
        Assert.Equal(["private_key_jwt"], List("token_endpoint_auth_methods_supported"));
        Assert.Equal(["private_key_jwt"], List("revocation_endpoint_auth_methods_supported"));
        Assert.Equal(["none"], List("introspection_endpoint_auth_methods_supported"));
        Assert.Equal(["ES256", "PS256", "RS256"], List("token_endpoint_auth_signing_alg_values_supported").Order(StringComparer.Ordinal));
        Assert.Equal(["ES256", "PS256", "RS256"], List("revocation_endpoint_auth_signing_alg_values_supported").Order(StringComparer.Ordinal));
        Assert.Empty(List("response_types_supported"));
        Assert.Equal(["urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"], List("grant_types_supported"));
        Assert.False(document.TryGetProperty("id_token_signing_alg_values_supported", out _), "The control plane issues no ID tokens and must not say it does.");
        Assert.False(document.TryGetProperty("authorization_endpoint", out _), "There is no authorization endpoint.");

        // The assertion audience the spec allows besides the token endpoint is the issuer itself.
        var agent = await subactid.RegisterAgentAsync();
        using var revoked = await subactid.Http.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "not-a-token",
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = subactid.ClientAssertion(agent, audience: subactid.Issuer),
        }));
        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
    }

    /// <summary>15. The token endpoint refuses what it does not do as such: an unknown grant type is <c>unsupported_grant_type</c>, and a request without <c>scope</c> is <c>invalid_request</c>, never a token for some default scope.</summary>
    [Fact]
    public async Task A_request_the_token_endpoint_does_not_do_is_refused_as_such()
    {
        var since = DateTimeOffset.UtcNow;
        var agent = await subactid.RegisterAgentAsync();

        using var unknown = await subactid.Http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = subactid.ClientAssertion(agent),
            ["scope"] = "jira:read",
        }));
        await LiveInstance.AssertOAuthErrorAsync(unknown, HttpStatusCode.BadRequest, "unsupported_grant_type");
        await AssertDeniedAsync(null, since, "unsupported_grant_type");

        var subjectToken = subactid.SubjectToken(subactid.NewHuman());
        using var unscoped = await subactid.Http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = subactid.ClientAssertion(agent),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["resource"] = Jira,
        }));
        await LiveInstance.AssertOAuthErrorAsync(unscoped, HttpStatusCode.BadRequest, "invalid_request", subjectToken);
        await AssertDeniedAsync(null, since, "invalid_request");
    }

    /// <summary>
    /// 16. Only the agent a token was issued to can revoke it, and nobody can use revocation to
    /// probe: another agent's token, another agent's grant and something that is no token at all
    /// all get the same empty <c>200</c>, nothing is revoked, and each refusal is recorded.
    /// </summary>
    [Fact]
    public async Task Only_the_agent_a_token_was_issued_to_can_revoke_it_and_the_answer_reveals_nothing()
    {
        var since = DateTimeOffset.UtcNow;
        var owner = await subactid.RegisterAgentAsync();
        var other = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();

        using var response = await subactid.ExchangeAsync(owner, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);
        var accessToken = token.GetProperty("access_token").GetString()!;
        var grant = token.GetProperty("refresh_token").GetString()!;

        // The same answer for a token that is someone else's and one that does not exist.
        foreach (var target in new[] { accessToken, grant, "not-a-token-" + Guid.NewGuid().ToString("N") })
        {
            using var revocation = await subactid.RevokeAsync(other, target);
            Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);
            var body = await revocation.Content.ReadAsStringAsync();
            Assert.True(body.Length == 0, $"A refused revocation must answer the same empty body as any other, but answered: {body}");
        }

        // Nothing was revoked: the token is live and its task renews.
        Assert.True((await subactid.IntrospectAsync(accessToken)).GetProperty("active").GetBoolean());
        using var renewed = await subactid.RefreshAsync(owner, grant);
        await LiveInstance.TokenAsync(renewed);

        // Each attempt is a refusal on the record, attributed to the agent that made it, under
        // the reason spec section 7.6 gives it.
        var refused = (await subactid.DenialsAsync(other, since))
            .Where(d => d.GetProperty("event").GetString() == "token.denied" && d.GetProperty("reason").GetString() == "revocation_not_owner")
            .ToList();
        Assert.True(refused.Count >= 3, $"Expected a token.denied with reason revocation_not_owner for each of the three refused revocations by {other.AgentId}, found {refused.Count}.");
    }

    /// <summary>
    /// 17. A token the agent revokes is inactive at the next introspection, with the time and a
    /// reason, and only that token: the task it belongs to carries on and its next token is live.
    /// </summary>
    [Fact]
    public async Task A_revoked_token_introspects_as_revoked_at_once_and_its_task_carries_on()
    {
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();

        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);
        var accessToken = token.GetProperty("access_token").GetString()!;
        Assert.True((await subactid.IntrospectAsync(accessToken)).GetProperty("active").GetBoolean());

        using var revocation = await subactid.RevokeAsync(agent, accessToken);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var revoked = await subactid.IntrospectAsync(accessToken);
        Assert.False(revoked.GetProperty("active").GetBoolean());
        Assert.True(revoked.TryGetProperty("revoked_at", out _), "A revoked token introspects with revoked_at.");
        Assert.False(string.IsNullOrEmpty(revoked.GetProperty("revocation_reason").GetString()), "A revoked token introspects with a revocation_reason.");
        Assert.False(revoked.TryGetProperty("sub", out _), "An inactive token reveals none of its claims.");

        // Revoking one token is not revoking the task: the grant still renews, and its token is live.
        using var renewed = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!);
        var next = await LiveInstance.TokenAsync(renewed);
        Assert.Equal(token.GetProperty("task_id").GetString(), next.GetProperty("task_id").GetString());
        Assert.True((await subactid.IntrospectAsync(next.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
    }

    /// <summary>
    /// 18. A back-channel logout ends what that session started and nothing else, a logout naming
    /// the person ends all of theirs, and neither blocks them. A logout token the identity provider
    /// did not sign changes nothing.
    /// </summary>
    [Fact]
    [Trait(LiveInstance.ReceiverTrait, "logout")]
    public async Task A_logout_ends_the_tasks_of_that_session_and_does_not_block_the_person()
    {
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();
        var loggedOut = "session-" + Guid.NewGuid().ToString("N");
        var stillOpen = "session-" + Guid.NewGuid().ToString("N");

        using var first = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, overrides: [("sid", loggedOut)]));
        var ended = await LiveInstance.TokenAsync(first);
        using var second = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human, overrides: [("sid", stillOpen)]));
        var running = await LiveInstance.TokenAsync(second);

        // Not signed by the identity provider: refused, and nothing ends.
        using var forgedKey = RSA.Create(2048);
        using var forged = await subactid.LogoutAsync(subactid.LogoutToken(human, loggedOut, forgedKey));
        Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
        Assert.True((await subactid.IntrospectAsync(ended.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());

        // The session's logout ends its task and leaves the other session's.
        using var logout = await subactid.LogoutAsync(subactid.LogoutToken(human, loggedOut));
        Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        Assert.False((await subactid.IntrospectAsync(ended.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
        using var refreshEnded = await subactid.RefreshAsync(agent, ended.GetProperty("refresh_token").GetString()!);
        await LiveInstance.AssertOAuthErrorAsync(refreshEnded, HttpStatusCode.BadRequest, "access_denied");
        Assert.True((await subactid.IntrospectAsync(running.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());

        // A logout of the person ends every task of theirs.
        using var everything = await subactid.LogoutAsync(subactid.LogoutToken(human));
        Assert.Equal(HttpStatusCode.OK, everything.StatusCode);
        Assert.False((await subactid.IntrospectAsync(running.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());

        // A logout revokes and does not block: the person signs in again and starts a new task.
        Assert.Null(await subactid.SponsorBlockAsync(human));
        using var again = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.TokenAsync(again);
    }

    /// <summary>
    /// 19. A provisioning client deactivating a person blocks them: what was running ends, nothing
    /// new starts, and the block is the provisioning feed's. Reactivating lets them start again and
    /// brings nothing back. A client without the credential is refused before anything is read.
    /// </summary>
    [Fact]
    [Trait(LiveInstance.ReceiverTrait, "scim")]
    public async Task A_provisioning_deactivation_blocks_the_person_until_they_are_reactivated()
    {
        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();

        using var refused = await subactid.ScimAsync(HttpMethod.Get, "/Users", credential: "not-the-credential-" + Guid.NewGuid().ToString("N"));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        // The person is provisioned under the identifier tasks are keyed by.
        using var created = await subactid.ScimAsync(HttpMethod.Post, "/Users", $$"""
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "{{human}}@conformance.example", "externalId": "{{human}}", "active": true}
            """);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var userId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!;

        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);

        using var deactivated = await subactid.ScimAsync(HttpMethod.Patch, "/Users/" + Uri.EscapeDataString(userId), """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": false}]}
            """);
        Assert.Equal(HttpStatusCode.OK, deactivated.StatusCode);

        Assert.False((await subactid.IntrospectAsync(token.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
        using var refresh = await subactid.RefreshAsync(agent, token.GetProperty("refresh_token").GetString()!);
        await LiveInstance.AssertOAuthErrorAsync(refresh, HttpStatusCode.BadRequest, "access_denied");
        using var blocked = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.AssertOAuthErrorAsync(blocked, HttpStatusCode.BadRequest, "access_denied");
        var block = await subactid.SponsorBlockAsync(human);
        Assert.True(block is not null, "A deactivated person has a block standing.");
        Assert.Equal("scim", block.Value.GetProperty("source").GetString());

        using var reactivated = await subactid.ScimAsync(HttpMethod.Patch, "/Users/" + Uri.EscapeDataString(userId), """
            {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": true}]}
            """);
        Assert.Equal(HttpStatusCode.OK, reactivated.StatusCode);
        Assert.Null(await subactid.SponsorBlockAsync(human));
        using var again = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.TokenAsync(again);

        // Revocation is permanent: the old task stays over.
        Assert.False((await subactid.IntrospectAsync(token.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
    }

    /// <summary>
    /// 20. A Shared Signals transmitter is heard only with its credential and its own key. A
    /// disabled account is blocked until the transmitter enables it again, a revoked session ends
    /// the person's tasks without blocking them, and the same event delivered twice is acted on once.
    /// </summary>
    [Fact]
    [Trait(LiveInstance.ReceiverTrait, "ssf")]
    public async Task A_transmitter_s_events_block_end_and_lift_as_they_say_and_only_with_its_credential_and_key()
    {
        const string SessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        const string AccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
        const string AccountEnabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

        var agent = await subactid.RegisterAgentAsync();
        var human = subactid.NewHuman();
        using var response = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var token = await LiveInstance.TokenAsync(response);

        // Without the push credential: refused before the token is read, and nothing changes.
        using var noCredential = await subactid.PushAsync(subactid.SecurityEvent(AccountDisabled, human), credential: "not-the-credential-" + Guid.NewGuid().ToString("N"));
        Assert.Equal(HttpStatusCode.Unauthorized, noCredential.StatusCode);

        // Signed by the identity provider rather than the transmitter: a different issuer's key
        // is not the transmitter's, whatever the token says.
        var signedByIdp = Jwt.SignRs256(subactid.Stub.IdpKey, subactid.Stub.TransmitterKid, Jwt.Payload(subactid.SecurityEvent(AccountDisabled, human)).Deserialize<Dictionary<string, object?>>()!);
        using var wrongKey = await subactid.PushAsync(signedByIdp);
        Assert.Equal(HttpStatusCode.BadRequest, wrongKey.StatusCode);
        Assert.True((await subactid.IntrospectAsync(token.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
        Assert.Null(await subactid.SponsorBlockAsync(human));

        // Disabled: what was running ends and nothing new starts. Delivered twice, acted on once.
        var disabled = subactid.SecurityEvent(AccountDisabled, human);
        using var delivered = await subactid.PushAsync(disabled);
        Assert.Equal(HttpStatusCode.Accepted, delivered.StatusCode);
        using var redelivered = await subactid.PushAsync(disabled);
        Assert.Equal(HttpStatusCode.Accepted, redelivered.StatusCode);
        Assert.False((await subactid.IntrospectAsync(token.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
        using var blocked = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.AssertOAuthErrorAsync(blocked, HttpStatusCode.BadRequest, "access_denied");
        var block = await subactid.SponsorBlockAsync(human);
        Assert.True(block is not null, "A disabled account has a block standing.");
        Assert.Equal("ssf", block.Value.GetProperty("source").GetString());

        // Enabled again: the person may start a new task.
        using var enabled = await subactid.PushAsync(subactid.SecurityEvent(AccountEnabled, human));
        Assert.Equal(HttpStatusCode.Accepted, enabled.StatusCode);
        Assert.Null(await subactid.SponsorBlockAsync(human));
        using var restarted = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        var restartedToken = await LiveInstance.TokenAsync(restarted);

        // A revoked session ends what is running, and blocks nobody.
        using var sessionRevoked = await subactid.PushAsync(subactid.SecurityEvent(SessionRevoked, human));
        Assert.Equal(HttpStatusCode.Accepted, sessionRevoked.StatusCode);
        Assert.False((await subactid.IntrospectAsync(restartedToken.GetProperty("access_token").GetString()!)).GetProperty("active").GetBoolean());
        Assert.Null(await subactid.SponsorBlockAsync(human));
        using var afterSessions = await subactid.ExchangeAsync(agent, subactid.SubjectToken(human));
        await LiveInstance.TokenAsync(afterSessions);
    }

    /// <summary>The instance's discovery document, which is where the JWKS anyone can fetch is named.</summary>
    private async Task<JsonElement> DiscoveryAsync() =>
        await subactid.Http.GetFromJsonAsync<JsonElement>(new Uri($"{subactid.Issuer.TrimEnd('/')}/.well-known/openid-configuration"));

    private static byte[] FromHex(string hex)
    {
        Assert.Matches("^[0-9a-f]*$", hex);
        return Convert.FromHexString(hex);
    }

    private static string ToHex(byte[] bytes) => Convert.ToHexStringLower(bytes);

    private async Task AssertDeniedAsync(ConformanceAgent? agent, DateTimeOffset since, string reason)
    {
        var denials = await subactid.DenialsAsync(agent, since);
        Assert.True(
            denials.Any(d => d.GetProperty("reason").GetString() == reason && d.GetProperty("decision").GetString() == "deny"),
            $"No denial with reason '{reason}' was written to the audit ledger; found: {string.Join(", ", denials.Select(d => d.GetProperty("reason").GetString()))}.");
    }
}
