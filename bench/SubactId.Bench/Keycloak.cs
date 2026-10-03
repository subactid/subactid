using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SubactId.Bench;

// Creates the rig's users and signs them in to get subject tokens.
internal sealed class Keycloak(HttpClient http, Uri baseUrl, string realm, string clientId, string adminUser, string adminPassword)
{
    private readonly Uri tokenEndpoint = new(baseUrl, $"/realms/{realm}/protocol/openid-connect/token");
    private readonly Uri adminTokenEndpoint = new(baseUrl, "/realms/master/protocol/openid-connect/token");
    private readonly SemaphoreSlim adminTokenLock = new(1, 1);
    private (string Value, DateTimeOffset ExpiresAt)? adminToken;

    // Creates the rig's users if missing and returns them. Passwords derive from the username,
    // since these throwaway accounts exist only inside the rig.
    public async Task<IReadOnlyList<BenchUser>> EnsureUsersAsync(int count, CancellationToken cancellationToken)
    {
        var users = new List<BenchUser>(count);
        for (var i = 0; i < count; i++)
        {
            var username = $"bench-{i:D4}";
            var password = $"pw-{username}";
            await EnsureUserAsync(username, password, cancellationToken);
            users.Add(new BenchUser(username, password));
        }

        return users;
    }

    private async Task EnsureUserAsync(string username, string password, CancellationToken cancellationToken)
    {
        var token = await AdminTokenAsync(cancellationToken);
        using var find = new HttpRequestMessage(HttpMethod.Get, new Uri(baseUrl, $"/admin/realms/{realm}/users?username={Uri.EscapeDataString(username)}&exact=true"));
        find.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var found = await http.SendAsync(find, cancellationToken);
        found.EnsureSuccessStatusCode();
        using (var document = JsonDocument.Parse(await found.Content.ReadAsStringAsync(cancellationToken)))
        {
            if (document.RootElement.GetArrayLength() > 0)
            {
                return;
            }
        }

        using var create = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUrl, $"/admin/realms/{realm}/users"))
        {
            // The realm's user profile requires firstName, lastName and email, and requiredActions
            // must be empty, or sign-in fails with "Account is not fully set up".
            Content = JsonContent.Create(new
            {
                username,
                enabled = true,
                emailVerified = true,
                firstName = "Bench",
                lastName = username,
                email = $"{username}@bench.invalid",
                requiredActions = Array.Empty<string>(),
                credentials = new[] { new { type = "password", value = password, temporary = false } },
            }),
        };
        create.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var created = await http.SendAsync(create, cancellationToken);
        if (created.StatusCode is not (HttpStatusCode.Created or HttpStatusCode.Conflict))
        {
            throw new InvalidOperationException($"Keycloak answered {(int)created.StatusCode} creating {username}.");
        }
    }

    // Signs a user in and returns their subject token.
    public async Task<(string Token, DateTimeOffset ExpiresAt)> SignInAsync(BenchUser user, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = clientId,
            ["username"] = user.Username,
            ["password"] = user.Password,
        });

        using var response = await http.PostAsync(tokenEndpoint, form, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Keycloak refused to sign {user.Username} in: {(int)response.StatusCode}.");
        }

        using var document = JsonDocument.Parse(body);
        var token = document.RootElement.GetProperty("access_token").GetString()!;
        var expiresIn = document.RootElement.GetProperty("expires_in").GetInt32();
        return (token, DateTimeOffset.UtcNow.AddSeconds(expiresIn));
    }

    private async Task<string> AdminTokenAsync(CancellationToken cancellationToken)
    {
        await adminTokenLock.WaitAsync(cancellationToken);
        try
        {
            if (adminToken is { } held && held.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
            {
                return held.Value;
            }

            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = "admin-cli",
                ["username"] = adminUser,
                ["password"] = adminPassword,
            });

            using var response = await http.PostAsync(adminTokenEndpoint, form, cancellationToken);
            response.EnsureSuccessStatusCode();
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var value = document.RootElement.GetProperty("access_token").GetString()!;
            var expiresIn = document.RootElement.GetProperty("expires_in").GetInt32();
            adminToken = (value, DateTimeOffset.UtcNow.AddSeconds(expiresIn));
            return value;
        }
        finally
        {
            adminTokenLock.Release();
        }
    }
}

internal sealed record BenchUser(string Username, string Password);
