using System.Buffers.Text;
using System.Net.Http;
using System.Text.Json;
using SubactId.Core.Agents;
using SubactId.Tokens;
using SubactId.Tokens.Signing;
using SubactId.Tokens.Upstream;

namespace SubactId.Tokens.ClientAuth;

/// <summary>
/// Authenticates an agent from a <c>private_key_jwt</c> client assertion (RFC 7523 section 3).
/// <c>iss</c> and <c>sub</c> name the agent, <c>aud</c> is this control plane, the key is one the
/// agent registered, the lifetime is short and the <c>jti</c> is new. The signature is checked
/// before any claim, and the <c>jti</c> is recorded last. Never throws for a bad assertion.
/// </summary>
public sealed class ClientAssertionAuthenticator
{
    /// <summary>Leeway applied to every time-based claim.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(60);

    /// <summary>Longest an assertion may claim to live (<c>exp</c> minus now). Bounds the replay store too.</summary>
    public static readonly TimeSpan MaxAssertionLifetime = TimeSpan.FromMinutes(5);

    /// <summary>How often expired replay records are purged, at most.</summary>
    public static readonly TimeSpan PurgeInterval = TimeSpan.FromMinutes(1);

    /// <summary>Longest <c>jti</c> accepted.</summary>
    public const int MaxJtiLength = 256;

    /// <summary>Longest <c>instance</c> accepted. It is copied into the token, so it is bounded.</summary>
    public const int MaxInstanceLength = 128;

    private readonly IAgentRepository agents;
    private readonly IAgentKeys keys;
    private readonly IAssertionReplayStore replays;
    private readonly TimeProvider clock;
    private readonly string[] acceptedAudiences;
    private readonly ReplayPurgeGate purgeGate;

    /// <summary>Creates the authenticator.</summary>
    /// <param name="agents">Agent registrations.</param>
    /// <param name="keys">Agents' published keys.</param>
    /// <param name="replays">Replay protection.</param>
    /// <param name="issuer">This control plane's issuer URL; the assertion's <c>aud</c> must be it or its token endpoint.</param>
    /// <param name="clock">Time source.</param>
    /// <param name="purgeGate">Process-wide throttle for purging expired replay records; a private one when omitted.</param>
    public ClientAssertionAuthenticator(IAgentRepository agents, IAgentKeys keys, IAssertionReplayStore replays, Uri issuer, TimeProvider clock, ReplayPurgeGate? purgeGate = null)
    {
        ArgumentNullException.ThrowIfNull(agents);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(replays);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(clock);

        this.agents = agents;
        this.keys = keys;
        this.replays = replays;
        this.clock = clock;
        this.purgeGate = purgeGate ?? new ReplayPurgeGate();
        var root = IssuerUrl.Canonical(issuer);
        acceptedAudiences = [root, root + "/oauth2/token"];
    }

    /// <summary>The <c>aud</c> values an assertion may carry.</summary>
    public IReadOnlyList<string> AcceptedAudiences => acceptedAudiences;

    /// <summary>Authenticates <paramref name="assertion"/>.</summary>
    /// <param name="assertion">The client assertion JWT.</param>
    /// <param name="clientId">The <c>client_id</c> form parameter, if the client sent one; must match the assertion's issuer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<ClientAuthentication> AuthenticateAsync(string? assertion, string? clientId = null, CancellationToken cancellationToken = default) =>
        AuthenticateAsync(assertion, clientId, acceptDisabled: false, cancellationToken);

    /// <summary>
    /// Authenticates <paramref name="assertion"/> for a request that can only take access away,
    /// such as an agent revoking its own token. Every check applies as in
    /// <see cref="AuthenticateAsync(string?, string?, CancellationToken)"/>, except that a disabled
    /// agent is accepted: disabling an agent must not stop it giving up what it holds.
    /// </summary>
    /// <param name="assertion">The client assertion JWT.</param>
    /// <param name="clientId">The <c>client_id</c> form parameter, if the client sent one; must match the assertion's issuer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<ClientAuthentication> AuthenticateToRevokeAsync(string? assertion, string? clientId = null, CancellationToken cancellationToken = default) =>
        AuthenticateAsync(assertion, clientId, acceptDisabled: true, cancellationToken);

    private async Task<ClientAuthentication> AuthenticateAsync(string? assertion, string? clientId, bool acceptDisabled, CancellationToken cancellationToken)
    {
        if (!JwsSegments.TryParse(assertion, out var segments))
        {
            return ClientAuthentication.Reject(ClientAssertionRejection.Malformed);
        }

        JwsHeader? header;
        byte[] signature;
        JsonDocument payload;
        try
        {
            header = JsonSerializer.Deserialize<JwsHeader>(Base64Url.DecodeFromChars(segments.Header));
            signature = Base64Url.DecodeFromChars(segments.Signature);
            payload = JsonDocument.Parse(Base64Url.DecodeFromChars(segments.Payload));
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return ClientAuthentication.Reject(ClientAssertionRejection.Malformed);
        }

        using (payload)
        {
            var claims = payload.RootElement;
            if (header is null || header.Crit is not null || string.IsNullOrEmpty(header.Kid) || claims.ValueKind != JsonValueKind.Object)
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.Malformed);
            }

            if (header.Alg is null || !UpstreamKey.AllowedAlgorithms.Contains(header.Alg))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.UnsupportedAlgorithm);
            }

            // Who claims to be calling. Both iss and sub name the client (RFC 7523 section 3, items 1 and 2).
            var issuer = GetString(claims, "iss");
            var subject = GetString(claims, "sub");
            // Which copy of the agent is acting. Self-reported by the agent and never verified.
            var instance = GetString(claims, "instance");
            // Bounded, and free of control characters like iss, sub and jti: it is signed into every
            // token and every tool server is told to log act, so a newline here would forge a log line.
            if (instance is { Length: > MaxInstanceLength } || (instance?.Any(char.IsControl) ?? false))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.Malformed);
            }

            // A blank instance is treated as absent.
            if (string.IsNullOrWhiteSpace(instance))
            {
                instance = null;
            }

            // A control character is refused before the agent is looked up. No agent id has one, and
            // Postgres rejects a NUL in text.
            if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(subject) || issuer.Any(char.IsControl) || subject.Any(char.IsControl))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.Malformed);
            }

            if (!string.Equals(issuer, subject, StringComparison.Ordinal))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.IssuerSubjectMismatch);
            }

            if (clientId is not null && !string.Equals(clientId, issuer, StringComparison.Ordinal))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.ClientIdMismatch);
            }

            var agent = await agents.FindAsync(issuer, cancellationToken);
            if (agent is null)
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.UnknownAgent);
            }

            // Keys come from the agent's JWKS URL or its inline set (spec section 2).
            if (agent.JwksUri is null && agent.Jwks is null)
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.NoRegisteredKeys);
            }

            // The key, from the agent's own JWKS only.
            UpstreamKey? key;
            try
            {
                var snapshot = await keys.GetAsync(agent, cancellationToken);
                if (!snapshot.Keys.TryGetValue(header.Kid, out key))
                {
                    snapshot = await keys.RefreshForUnknownKidAsync(agent, cancellationToken);
                    snapshot.Keys.TryGetValue(header.Kid, out key);
                }
            }
            catch (HttpRequestException exception) when (DestinationRefusedException.IsIn(exception))
            {
                // The JWKS URL resolves only to addresses this control plane is configured not to
                // reach. Not an outage: asking again is refused again.
                return ClientAuthentication.Reject(ClientAssertionRejection.KeysRefused);
            }
            catch (Exception exception) when (exception is HttpRequestException or UpstreamDiscoveryException or TaskCanceledException)
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.KeysUnavailable);
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                // The registered JWKS URL is unusable, for example not https.
                return ClientAuthentication.Reject(ClientAssertionRejection.NoRegisteredKeys);
            }

            if (key is null)
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.UnknownKey);
            }

            if (!key.Supports(header.Alg))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.KeyMismatch);
            }

            if (!key.Verify(header.Alg, segments.SigningInput, signature))
            {
                return ClientAuthentication.Reject(ClientAssertionRejection.InvalidSignature);
            }

            // The caller has now proved it holds the agent's key. Before this point a disabled agent
            // looks like any other rejection, so agent ids cannot be enumerated. From here every
            // rejection is attributed to this agent and belongs in the ledger.
            ClientAuthentication Proven(ClientAssertionRejection reason) => ClientAuthentication.Reject(reason, agent.AgentId);

            if (!agent.Enabled && !acceptDisabled)
            {
                return Proven(ClientAssertionRejection.AgentDisabled);
            }

            // Claims are checked only after the signature.
            if (!AudienceMatches(claims))
            {
                return Proven(ClientAssertionRejection.WrongAudience);
            }

            var now = clock.GetUtcNow();
            if (!claims.TryGetProperty("exp", out var expElement))
            {
                return Proven(ClientAssertionRejection.MissingExpiry);
            }

            if (!TryGetTime(expElement, out var expiresAt))
            {
                return Proven(ClientAssertionRejection.Malformed);
            }

            if (now >= expiresAt + ClockSkew)
            {
                return Proven(ClientAssertionRejection.Expired);
            }

            if (expiresAt > now + MaxAssertionLifetime + ClockSkew)
            {
                return Proven(ClientAssertionRejection.LifetimeTooLong);
            }

            foreach (var name in new[] { "nbf", "iat" })
            {
                if (claims.TryGetProperty(name, out var element))
                {
                    if (!TryGetTime(element, out var time))
                    {
                        return Proven(ClientAssertionRejection.Malformed);
                    }

                    if (time > now + ClockSkew)
                    {
                        return Proven(ClientAssertionRejection.NotYetValid);
                    }
                }
            }

            var jti = GetString(claims, "jti");
            if (string.IsNullOrEmpty(jti))
            {
                return Proven(ClientAssertionRejection.MissingJti);
            }

            // Recorded for replay protection, so it must be storable.
            if (jti.Length > MaxJtiLength || jti.Any(char.IsControl))
            {
                return Proven(ClientAssertionRejection.Malformed);
            }

            await PurgeOccasionallyAsync(now, cancellationToken);
            if (!await replays.TryRecordAsync(agent.AgentId, jti, expiresAt + ClockSkew, cancellationToken))
            {
                return Proven(ClientAssertionRejection.Replayed);
            }

            return ClientAuthentication.Accept(agent, instance);
        }
    }

    private bool AudienceMatches(JsonElement claims)
    {
        if (!claims.TryGetProperty("aud", out var aud))
        {
            return false;
        }

        return aud.ValueKind switch
        {
            JsonValueKind.String => acceptedAudiences.Contains(aud.GetString(), StringComparer.Ordinal),
            JsonValueKind.Array => aud.EnumerateArray().Any(a => a.ValueKind == JsonValueKind.String && acceptedAudiences.Contains(a.GetString(), StringComparer.Ordinal)),
            _ => false,
        };
    }

    private async Task PurgeOccasionallyAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (purgeGate.TryClaim(now))
        {
            await replays.PurgeExpiredAsync(now, cancellationToken);
        }
    }

    private static string? GetString(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool TryGetTime(JsonElement element, out DateTimeOffset time)
    {
        time = default;
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetDouble(out var seconds) || double.IsNaN(seconds) || double.IsInfinity(seconds) || seconds < 0 || seconds > 253_402_300_799)
        {
            return false;
        }

        time = DateTimeOffset.FromUnixTimeSeconds((long)Math.Floor(seconds));
        return true;
    }
}

/// <summary>Why a client assertion was rejected. Every value is a stable audit reason; the token endpoint answers <c>invalid_client</c> for all of them.</summary>
public enum ClientAssertionRejection
{
    /// <summary>The assertion was accepted.</summary>
    None,

    /// <summary>Not a canonical compact JWS, or a header or claim has the wrong shape.</summary>
    Malformed,

    /// <summary>The <c>alg</c> header is not RS256, PS256 or ES256.</summary>
    UnsupportedAlgorithm,

    /// <summary><c>iss</c> and <c>sub</c> differ.</summary>
    IssuerSubjectMismatch,

    /// <summary>The <c>client_id</c> parameter names a different client than the assertion.</summary>
    ClientIdMismatch,

    /// <summary>No agent is registered under the assertion's issuer.</summary>
    UnknownAgent,

    /// <summary>The agent is disabled. Reported only for an assertion that verified against the agent's key.</summary>
    AgentDisabled,

    /// <summary>The agent has no registered JWKS URL, or the registered one cannot be used.</summary>
    NoRegisteredKeys,

    /// <summary>The agent's JWKS could not be fetched and nothing was cached.</summary>
    KeysUnavailable,

    /// <summary>
    /// The agent's JWKS URL resolves only to addresses this control plane is configured not to
    /// reach, and nothing was cached. A standing refusal of the registration, not an outage.
    /// </summary>
    KeysRefused,

    /// <summary>The <c>kid</c> is not in the agent's JWKS, even after a refresh.</summary>
    UnknownKey,

    /// <summary>The named key cannot be used with the assertion's algorithm.</summary>
    KeyMismatch,

    /// <summary>The signature does not verify against the agent's key.</summary>
    InvalidSignature,

    /// <summary>The <c>aud</c> claim is not this control plane.</summary>
    WrongAudience,

    /// <summary>No <c>exp</c> claim.</summary>
    MissingExpiry,

    /// <summary>The assertion has expired, beyond clock skew.</summary>
    Expired,

    /// <summary>The assertion claims to live longer than <see cref="ClientAssertionAuthenticator.MaxAssertionLifetime"/>.</summary>
    LifetimeTooLong,

    /// <summary>The assertion's <c>nbf</c> or <c>iat</c> is in the future, beyond clock skew.</summary>
    NotYetValid,

    /// <summary>No <c>jti</c> claim.</summary>
    MissingJti,

    /// <summary>The <c>jti</c> was already used.</summary>
    Replayed,
}

/// <summary>Outcome of client authentication.</summary>
/// <param name="Agent">The authenticated agent, when accepted.</param>
/// <param name="Reason">Why the assertion was rejected; <see cref="ClientAssertionRejection.None"/> when accepted.</param>
/// <param name="Instance">What the agent said about which copy of it is acting, when it said anything.</param>
/// <param name="ProvenAgentId">
/// The agent whose key verified the assertion, on a rejection after the signature check.
/// <c>null</c> for every rejection up to and including
/// <see cref="ClientAssertionRejection.InvalidSignature"/>. Every denial goes in the ledger: one
/// with this set names the agent, and one without it names nobody and is summarised (spec section
/// 7.2), since nothing in an unverified assertion is worth attributing.
/// </param>
public sealed record ClientAuthentication(Agent? Agent, ClientAssertionRejection Reason, string? Instance = null, string? ProvenAgentId = null)
{
    /// <summary>Whether the assertion was accepted.</summary>
    public bool IsAuthenticated => Agent is not null;

    /// <summary>
    /// Whether the caller proved it holds a registered agent's key, accepted or not. Decides
    /// whether a denial is recorded in the ledger.
    /// </summary>
    public bool IsAttributable => Agent is not null || ProvenAgentId is not null;

    /// <summary>The agent this outcome is attributable to, accepted or not; <c>null</c> when nobody proved anything.</summary>
    public string? AttributedAgentId => Agent?.AgentId ?? ProvenAgentId;

    internal static ClientAuthentication Accept(Agent agent, string? instance = null) => new(agent, ClientAssertionRejection.None, instance);

    internal static ClientAuthentication Reject(ClientAssertionRejection reason) => new(null, reason);

    /// <summary>A rejection by an agent whose key verified the assertion.</summary>
    internal static ClientAuthentication Reject(ClientAssertionRejection reason, string provenAgentId) => new(null, reason, null, provenAgentId);
}
