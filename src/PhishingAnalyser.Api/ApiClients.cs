using System.Security.Cryptography;
using System.Text;

namespace PhishingAnalyser.Api;

/// <summary>One installation allowed to call the API. Only the SHA-256 of its key is stored.</summary>
public sealed class ApiClientOptions
{
    public string Name { get; set; } = "";
    public string KeySha256 { get; set; } = "";
}

/// <summary>
/// Per-client API keys: each extension install gets its own key, so one leaked key can be revoked on its own
/// (delete its entry, restart), and rate limits and logs are per client instead of per shared secret.
/// The server stores only hashes, so a leaked config file doesn't leak working keys.
///
/// This is still a bearer secret held by the extension - it identifies an installation, not a person.
/// For a multi-user service the next step is real sign-in (Google OAuth via chrome.identity -> a short-lived JWT).
/// </summary>
public sealed class ApiClients
{
    public const string HeaderName = "X-Api-Key";
    public const string ItemKey = "api-client";

    private readonly (string Name, byte[] Hash)[] _clients;

    public ApiClients(IEnumerable<ApiClientOptions> clients, string? legacySharedKey)
    {
        var list = clients
            .Where(c => !string.IsNullOrWhiteSpace(c.Name) && !string.IsNullOrWhiteSpace(c.KeySha256))
            .Select(c => (c.Name, Convert.FromHexString(c.KeySha256.Trim())))
            .ToList();
        // The original single "ApiKey" setting still works, as a client called "shared".
        if (!string.IsNullOrEmpty(legacySharedKey))
            list.Add(("shared", Hash(legacySharedKey)));
        _clients = [.. list];
    }

    /// <summary>False when no keys are configured: the API is open (local development).</summary>
    public bool Enabled => _clients.Length > 0;

    public int Count => _clients.Length;

    /// <summary>The client's name, or null. Compares against every entry in constant time, with no early exit.</summary>
    public string? Identify(string? suppliedKey)
    {
        if (string.IsNullOrEmpty(suppliedKey))
            return null;
        var supplied = Hash(suppliedKey);
        string? match = null;
        foreach (var (name, hash) in _clients)
            if (CryptographicOperations.FixedTimeEquals(supplied, hash))
                match = name;
        return match;
    }

    public static byte[] Hash(string key) => SHA256.HashData(Encoding.UTF8.GetBytes(key));

    /// <summary>A new random key (256 bits) and the settings line that registers it.</summary>
    public static (string Key, string Sha256) NewKey()
    {
        var key = "pa_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (key, Convert.ToHexString(Hash(key)).ToLowerInvariant());
    }
}
