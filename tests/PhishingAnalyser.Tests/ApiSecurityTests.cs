using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PhishingAnalyser.Api;

namespace PhishingAnalyser.Tests;

/// <summary>Per-client API keys, per-client rate limits, trusted proxies and the internal metrics endpoint.</summary>
public class ApiSecurityTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly (string Key, string Sha256) Laptop = ApiClients.NewKey();
    private static readonly (string Key, string Sha256) Phone = ApiClients.NewKey();
    private static readonly object Body = new { subject = "hello" };

    private WebApplicationFactory<Program> WithClients(int perMinute = 60) => factory.WithWebHostBuilder(b => b
        .UseSetting("ApiClients:0:Name", "laptop").UseSetting("ApiClients:0:KeySha256", Laptop.Sha256)
        .UseSetting("ApiClients:1:Name", "phone").UseSetting("ApiClients:1:KeySha256", Phone.Sha256)
        .UseSetting("RateLimit:PerMinute", perMinute.ToString()));

    private static HttpClient Keyed(WebApplicationFactory<Program> app, string? key)
    {
        var client = app.CreateClient();
        if (key is not null)
            client.DefaultRequestHeaders.Add(ApiClients.HeaderName, key);
        return client;
    }

    [Fact]
    public void Keys_are_identified_by_hash_only()
    {
        var clients = new ApiClients([new() { Name = "laptop", KeySha256 = Laptop.Sha256 }], legacySharedKey: null);
        Assert.StartsWith("pa_", Laptop.Key);
        Assert.Equal("laptop", clients.Identify(Laptop.Key));
        Assert.Null(clients.Identify(Phone.Key));
        Assert.Null(clients.Identify(Laptop.Sha256)); // the stored hash is not itself a working key
        Assert.Null(clients.Identify(""));
    }

    [Fact]
    public async Task Each_registered_client_key_works_and_unknown_keys_are_rejected()
    {
        var app = WithClients();
        Assert.Equal(HttpStatusCode.OK, (await Keyed(app, Laptop.Key).PostAsJsonAsync("/api/v1/analyse", Body)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Keyed(app, Phone.Key).PostAsJsonAsync("/api/v1/analyse", Body)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Keyed(app, "pa_guessed").PostAsJsonAsync("/api/v1/analyse", Body)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Keyed(app, null).PostAsJsonAsync("/api/v1/analyse", Body)).StatusCode);
    }

    [Fact]
    public async Task Rate_limit_is_per_client_not_shared()
    {
        var app = WithClients(perMinute: 1);
        var laptop = Keyed(app, Laptop.Key);
        // Three requests against a limit of one: even if the fixed one-minute window happens to roll over
        // between two of them, at least one must be refused.
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
            statuses.Add((await laptop.PostAsJsonAsync("/api/v1/analyse", Body)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, statuses[0]);
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
        // Same IP (the test server), different client: its own bucket.
        Assert.Equal(HttpStatusCode.OK, (await Keyed(app, Phone.Key).PostAsJsonAsync("/api/v1/analyse", Body)).StatusCode);
    }

    [Fact]
    public void Proxy_addresses_come_from_configuration()
    {
        var app = factory.WithWebHostBuilder(b => b
            .UseSetting("ForwardedHeaders:KnownProxies:0", "172.30.57.1")
            .UseSetting("ForwardedHeaders:KnownNetworks:0", "10.8.0.0/24"));
        var options = app.Services.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

        Assert.Contains(IPAddress.Parse("172.30.57.1"), options.KnownProxies);
        Assert.Contains(options.KnownNetworks, n => n.Prefix.Equals(IPAddress.Parse("10.8.0.0")) && n.PrefixLength == 24);
        Assert.Equal(1, options.ForwardLimit);
    }

    [Fact]
    public async Task Metrics_are_served_only_on_the_internal_port()
    {
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/api/v1/analyse", Body);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/metrics")).StatusCode);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/metrics");
        request.Headers.Host = "localhost:9464";
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var text = await response.Content.ReadAsStringAsync();
        Assert.Contains("phishing_analyses", text);
        Assert.DoesNotContain("hello", text); // no email content in metrics
    }
}
