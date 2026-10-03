using System.Security.Cryptography;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Health;

/// <summary>Readiness: the active signing key can produce a signature that the published key set verifies.</summary>
public sealed class SigningKeyHealthCheck(SigningKeySet keys) : IHealthCheck
{
    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var nonce = RandomNumberGenerator.GetBytes(32);
        var token = Jws.Sign(keys, nonce, typ: "health");
        var usable = Jws.TryVerify(keys, token, out var header, out var payload)
            && header?.Kid == keys.Active.Kid
            && payload.AsSpan().SequenceEqual(nonce);

        return Task.FromResult(usable
            ? HealthCheckResult.Healthy($"Signing key '{keys.Active.Kid}' is usable; {keys.Keys.Count} key(s) published.")
            : HealthCheckResult.Unhealthy($"Signing key '{keys.Active.Kid}' failed a sign/verify round trip."));
    }
}
