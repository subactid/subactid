using SubactId.Tokens.Signing;

namespace SubactId.Server.Configuration;

/// <summary>
/// Turns <see cref="SigningOptions"/> into the runtime <see cref="SigningKeySet"/>. Outside
/// Development a missing key fails startup. In Development an ephemeral key is generated, and the
/// caller must log a warning.
/// </summary>
public static class SigningKeyBootstrap
{
    /// <summary>Loads the configured keys, or an ephemeral key in Development when none are configured.</summary>
    /// <param name="options">The signing configuration.</param>
    /// <param name="isDevelopment">Whether the host runs in the Development environment.</param>
    /// <param name="ephemeral">Set when a key was generated instead of loaded.</param>
    /// <exception cref="SigningKeyException">No key is configured outside Development, or a configured key is unusable.</exception>
    public static SigningKeySet Load(SigningOptions options, bool isDevelopment, out bool ephemeral)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Keys.Count == 0)
        {
            if (!isDevelopment)
            {
                throw new SigningKeyException(
                    "No signing key is configured. Set SubactId:Signing:Keys:0:Path (environment variable SubactId__Signing__Keys__0__Path) "
                    + "or SubactId:Signing:Keys:0:Pem. Keys are never generated automatically outside the Development environment.");
            }

            ephemeral = true;
            return SigningKeySet.CreateEphemeral();
        }

        ephemeral = false;
        return SigningKeySetLoader.Load(options.Sources, options.ActiveKid);
    }
}
