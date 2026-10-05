using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Tests;

/// <summary>End-to-end through the real HTTP pipeline with the real trained model.</summary>
public class ApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly string ModelPath = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "models", "phishing-content-model.zip"));

    private HttpClient CreateClient() => factory
        .WithWebHostBuilder(b => b.UseSetting("ContentModel:Path", ModelPath))
        .CreateClient();

    [Fact]
    public async Task Health_reports_model_loaded_with_version()
    {
        var json = await CreateClient().GetFromJsonAsync<JsonElement>("/health");
        Assert.True(json.GetProperty("contentModelLoaded").GetBoolean());
        Assert.False(string.IsNullOrEmpty(json.GetProperty("model").GetProperty("version").GetString()));
    }

    [Fact]
    public async Task Root_shows_a_landing_page_instead_of_a_404()
    {
        var response = await CreateClient().GetAsync("/");
        response.EnsureSuccessStatusCode();
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Phishing Email Analyser", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Marketing_email_is_reported_as_spam_not_phishing()
    {
        var response = await CreateClient().PostAsJsonAsync("/api/v1/analyse", new
        {
            subject = "50% off everything this weekend only!",
            senderName = "Northwind Outdoor",
            senderEmail = "deals@northwind-outdoor.com",
            body = "Shop our biggest sale of the year. Free shipping on orders over $50. Use code SAVE50 at checkout. Unsubscribe from these emails at any time.",
        });
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var content = json.GetProperty("breakdown").GetProperty("content");
        Assert.True(content.GetProperty("spamProbability").GetDouble() > content.GetProperty("probability").GetDouble());
        Assert.NotEqual("phishing", json.GetProperty("verdict").GetString());
        Assert.False(string.IsNullOrEmpty(json.GetProperty("modelVersion").GetString()));
    }

    [Fact]
    public async Task Classic_phish_is_flagged()
    {
        var response = await CreateClient().PostAsJsonAsync("/api/v1/analyse", new
        {
            subject = "Action required: your account has been limited",
            senderName = "PayPal Service",
            senderEmail = "security-alert@paypa1-support.com",
            body = "Dear customer, we noticed unusual activity on your account. Verify your information within 24 hours or your account will be permanently suspended. Click below to confirm your identity.",
            links = new[] { new { text = "https://www.paypal.com/verify", href = "http://185.22.4.9/pp/login" } },
        });

        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("phishing", json.GetProperty("verdict").GetString());
        Assert.True(json.GetProperty("score").GetDouble() > 0.9);
        Assert.NotEmpty(json.GetProperty("reasons").EnumerateArray());
    }

    [Fact]
    public async Task Ordinary_email_is_safe()
    {
        var response = await CreateClient().PostAsJsonAsync("/api/v1/analyse", new
        {
            subject = "Re: draft of chapter 3",
            senderName = "Lina Haddad",
            senderEmail = "lina.haddad@university.edu",
            body = "Thanks for the comments. I reworked the second section and moved the table into the appendix. Can you take another look when you have time?",
            links = new[] { new { text = "shared folder", href = "https://drive.google.com/drive/folders/abc" } },
        });

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("safe", json.GetProperty("verdict").GetString());
    }

    [Fact]
    public async Task Empty_request_is_rejected()
    {
        var response = await CreateClient().PostAsJsonAsync("/api/v1/analyse", new { });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Api_key_is_enforced_when_configured()
    {
        var client = factory.WithWebHostBuilder(b => b.UseSetting("ApiKey", "s3cret")).CreateClient();
        var body = new { subject = "hello" };

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/v1/analyse", body)).StatusCode);

        client.DefaultRequestHeaders.Add("X-Api-Key", "s3cret");
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/analyse", body)).StatusCode);
    }
}

[Collection(TimingSensitive.Name)]
public class ContentClassifierTests
{
    [Fact]
    public void Concurrent_requests_get_the_same_answers_as_sequential_ones()
    {
        var classifier = ContentClassifier.Load(Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "models", "phishing-content-model.zip")));
        var emails = Enumerable.Range(0, 64)
            .Select(i => i % 2 == 0
                ? ($"Your account {i} is suspended", "Verify your password within 24 hours or lose access.")
                : ($"Minutes of meeting {i}", "Attached are the notes from Tuesday. Let me know if I missed anything."))
            .ToArray();

        var sequential = emails.Select(e => classifier.Classify(e.Item1, e.Item2).Probability).ToArray();
        var parallel = new double[emails.Length];
        Parallel.For(0, emails.Length, new ParallelOptions { MaxDegreeOfParallelism = 16 },
            i => parallel[i] = classifier.Classify(emails[i].Item1, emails[i].Item2).Probability);

        Assert.Equal(sequential, parallel);
    }

    [Theory]
    [InlineData("WordFeatures.verify|your", "verify your")]
    [InlineData("WordFeatures.numtoken|hours", "<number> hours")]
    [InlineData("CharFeatures.<␂>|p|a", null)]
    [InlineData("WordFeatures.numtoken", null)]
    public void Slot_names_become_readable_terms(string slot, string? expected) =>
        Assert.Equal(expected, ContentClassifier.ToDisplayTerm(slot));
}
