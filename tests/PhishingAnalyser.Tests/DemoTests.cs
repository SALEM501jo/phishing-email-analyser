using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using PhishingAnalyser.Api;

namespace PhishingAnalyser.Tests;

/// <summary>The public "try it" page and its endpoint: open to anyone, so small, throttled and without outside lookups.</summary>
public class DemoTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly (string Key, string Sha256) Laptop = ApiClients.NewKey();

    private HttpClient Client(params (string Key, string Value)[] settings) => factory.WithWebHostBuilder(b =>
    {
        // Rules only (no models: every host that loads them costs ~500 MB), keys configured as in production.
        b.UseSetting("ContentModel:Path", "no-model.zip").UseSetting("ContentModel:TransformerPath", "no-transformer")
         .UseSetting("ApiClients:0:Name", "laptop").UseSetting("ApiClients:0:KeySha256", Laptop.Sha256);
        foreach (var (key, value) in settings)
            b.UseSetting(key, value);
    }).CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static readonly object Phish = new
    {
        subject = "Your account has been limited", senderName = "PayPal Security", senderEmail = "service@paypa1-secure-login.com",
        body = "Verify your identity within 24 hours.", linkText = "www.paypal.com", linkUrl = "http://185.22.4.9/paypal/login",
    };

    [Fact]
    public async Task Demo_analyses_without_a_key_while_the_real_api_still_requires_one()
    {
        var client = Client();
        var response = await client.PostAsJsonAsync("/api/v1/demo/analyse", Phish);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("phishing", json.GetProperty("verdict").GetString());
        var linkCodes = json.GetProperty("breakdown").GetProperty("links").GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("code").GetString());
        Assert.Contains("ip-url", linkCodes);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/analyse", Phish)).StatusCode);
    }

    [Fact]
    public async Task Demo_makes_no_outside_lookups()
    {
        var json = await (await Client().PostAsJsonAsync("/api/v1/demo/analyse", Phish)).Content.ReadFromJsonAsync<JsonElement>();
        // The reputation component (domain age, blocklists, short-link expansion) is never run for anonymous visitors.
        var breakdown = json.GetProperty("breakdown");
        Assert.True(!breakdown.TryGetProperty("reputation", out var reputation) || reputation.ValueKind == JsonValueKind.Null
                    || !reputation.GetProperty("evaluated").GetBoolean());
    }

    [Fact]
    public async Task Urls_written_in_the_body_are_checked_as_links()
    {
        var response = await Client().PostAsJsonAsync("/api/v1/demo/analyse", new { subject = "Invoice", body = "Pay here: http://185.22.4.9/pay now" });
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("ip-url", json.GetProperty("breakdown").GetProperty("links").GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("code").GetString()));
    }

    [Fact]
    public async Task Each_visitor_gets_a_small_allowance()
    {
        var client = Client(("Demo:PerMinute", "2"));
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
            statuses.Add((await client.PostAsJsonAsync("/api/v1/demo/analyse", Phish)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, statuses[0]);
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    [Fact]
    public async Task All_visitors_together_share_one_budget()
    {
        var client = Client(("Demo:PerMinute", "100"), ("Demo:TotalPerMinute", "1"));
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 4; i++)
            statuses.Add((await client.PostAsJsonAsync("/api/v1/demo/analyse", Phish)).StatusCode);
        Assert.Contains(HttpStatusCode.OK, statuses);
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    [Theory]
    [InlineData(301, 10)]
    [InlineData(10, 5001)]
    public async Task Oversized_input_is_rejected(int subjectLength, int bodyLength)
    {
        var response = await Client().PostAsJsonAsync("/api/v1/demo/analyse", new { subject = new string('a', subjectLength), body = new string('b', bodyLength) });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task The_page_is_served_with_a_strict_content_security_policy()
    {
        var client = Client();
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/try")).StatusCode);
        var page = await client.GetAsync("/try.html");
        page.EnsureSuccessStatusCode();
        var csp = string.Join(" ", page.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("default-src 'none'", csp);
        Assert.Contains("script-src 'self'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        var html = await page.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>", html);            // the policy forbids inline script, so the page must have none
        Assert.DoesNotContain(" style=", html);
        Assert.Contains("href=\"/try\"", await client.GetStringAsync("/"));
    }

    [Fact]
    public async Task The_demo_can_be_switched_off()
    {
        var client = Client(("Demo:Enabled", "false"));
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/api/v1/demo/analyse", Phish)).StatusCode);
        Assert.DoesNotContain("href=\"/try\"", await client.GetStringAsync("/"));
    }
}
