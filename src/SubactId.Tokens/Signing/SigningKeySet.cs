namespace SubactId.Tokens.Signing;

/// <summary>
/// The published signing keys and the active one. Every key appears in JWKS, so tokens signed
/// by an older key still verify. Only <see cref="Active"/> signs new tokens.
/// </summary>
public sealed class SigningKeySet : IDisposable
{
    private readonly Dictionary<string, SigningKey> byKid;

    /// <summary>Creates a set. Kids must be unique and <paramref name="activeKid"/> must name one of the keys.</summary>
    /// <param name="keys">Every key to publish, in publication order.</param>
    /// <param name="activeKid">The key to sign with.</param>
    /// <exception cref="SigningKeyException">The set is empty, has duplicate kids, or the active kid is unknown.</exception>
    public SigningKeySet(IReadOnlyList<SigningKey> keys, string activeKid)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentException.ThrowIfNullOrWhiteSpace(activeKid);

        if (keys.Count == 0)
        {
            throw new SigningKeyException("At least one signing key is required.");
        }

        byKid = new Dictionary<string, SigningKey>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            if (!byKid.TryAdd(key.Kid, key))
            {
                throw new SigningKeyException($"Signing key id '{key.Kid}' is used more than once.");
            }
        }

        if (!byKid.TryGetValue(activeKid, out var active))
        {
            throw new SigningKeyException($"Active signing key '{activeKid}' is not one of the configured keys ({string.Join(", ", byKid.Keys)}).");
        }

        Keys = keys;
        Active = active;
    }

    /// <summary>Every published key, in publication order.</summary>
    public IReadOnlyList<SigningKey> Keys { get; }

    /// <summary>The key new tokens are signed with.</summary>
    public SigningKey Active { get; }

    /// <summary>Returns the key with the given id, or <c>null</c>.</summary>
    /// <param name="kid">The key identifier.</param>
    public SigningKey? Find(string kid) => byKid.GetValueOrDefault(kid);

    /// <summary>The public JWKS document: every key, never any private material.</summary>
    public Jwks ToJwks() => new(Keys.Select(k => k.PublicJwk).ToList());

    /// <summary>A single freshly generated key. For development and tests only.</summary>
    public static SigningKeySet CreateEphemeral()
    {
        var key = SigningKey.Generate();
        return new SigningKeySet([key], key.Kid);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var key in Keys)
        {
            key.Dispose();
        }
    }
}
