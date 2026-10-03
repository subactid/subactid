using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>
/// Signs the demo user in. A real deployment signs the user in through a browser and hands the
/// agent the access token. The demo uses the password grant so it needs no interaction.
/// </summary>
internal sealed class Keycloak(HttpClient http, Uri baseUrl, string realm, string clientId)
{
    /// <summary>The realm's token endpoint.</summary>
    public Uri TokenEndpoint { get; } = new(baseUrl, $"/realms/{realm}/protocol/openid-connect/token");

    /// <summary>
    /// Signs the demo user in. A refusal is reported separately from an identity provider that is
    /// not ready yet.
    /// </summary>
    public async Task<SignIn> SignInAsync(string username, string password, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = clientId,
            ["username"] = username,
            ["password"] = password,
        });

        try
        {
            using var response = await http.PostAsync(TokenEndpoint, form, cancellationToken);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var body = document.RootElement;
            if (response.IsSuccessStatusCode)
            {
                return new SignIn(Jwt.Claim(body, "access_token"), null);
            }

            // A 400 is a refusal for this user. Anything else means the realm is not ready yet.
            return (int)response.StatusCode == 400
                ? new SignIn(null, $"{Jwt.Claim(body, "error")}: {Jwt.Claim(body, "error_description")}")
                : new SignIn(null, null);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or TaskCanceledException)
        {
            return new SignIn(null, null);
        }
    }

}

/// <summary>The human's token, or why they were refused; both <c>null</c> means the identity provider is not answering yet.</summary>
internal sealed record SignIn(string? AccessToken, string? Refusal);
