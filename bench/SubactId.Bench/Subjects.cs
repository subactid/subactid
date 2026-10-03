namespace SubactId.Bench;

// The humans a run acts for and their subject tokens, handed out round-robin.
internal sealed class Subjects
{
    private readonly Keycloak keycloak;
    private readonly BenchUser[] users;
    private readonly Held[] held;
    private int cursor = -1;

    private Subjects(Keycloak keycloak, IReadOnlyList<BenchUser> users)
    {
        this.keycloak = keycloak;
        this.users = [.. users];
        held = new Held[users.Count];
    }

    public int Count => users.Length;

    public static async Task<Subjects> SignInAsync(Keycloak keycloak, IReadOnlyList<BenchUser> users, CancellationToken cancellationToken)
    {
        var subjects = new Subjects(keycloak, users);
        for (var i = 0; i < users.Count; i++)
        {
            var (token, expiresAt) = await keycloak.SignInAsync(users[i], cancellationToken);
            subjects.held[i] = new Held(token, expiresAt);
        }

        return subjects;
    }

    // The next human's token. A token within five minutes of expiry is renewed first, since a
    // soak outlives the realm's token lifetime.
    public async Task<string> NextAsync(CancellationToken cancellationToken)
    {
        var index = (int)((uint)Interlocked.Increment(ref cursor) % (uint)users.Length);
        var current = Volatile.Read(ref held[index]);
        if (current.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            return current.Token;
        }

        var (token, expiresAt) = await keycloak.SignInAsync(users[index], cancellationToken);
        var replacement = new Held(token, expiresAt);
        Volatile.Write(ref held[index], replacement);
        return replacement.Token;
    }

    private sealed record Held(string Token, DateTimeOffset ExpiresAt);
}
