using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using PhishingAnalyser.Api;

namespace PhishingAnalyser.Tests;

public class FeedbackTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private HttpClient Client(string db) => factory.WithWebHostBuilder(b => b.UseSetting("Feedback:DatabasePath", db)).CreateClient();

    private static string TempDb() => Path.Combine(Path.GetTempPath(), $"feedback-{Guid.NewGuid():N}.db");

    [Fact]
    public async Task Feedback_is_stored_and_summarised_without_content()
    {
        var client = Client(TempDb());
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/api/v1/feedback",
            new { correct = false, verdict = "phishing", score = 0.81, modelVersion = "test", reasonCodes = new[] { "shortener" } })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/api/v1/feedback",
            new { correct = true, verdict = "phishing", score = 0.97, reasonCodes = new[] { "lookalike-domain" } })).StatusCode);

        var summary = await client.GetFromJsonAsync<JsonElement>("/api/v1/feedback/summary");
        var phishing = summary.EnumerateArray().Single(r => r.GetProperty("verdict").GetString() == "phishing");
        Assert.Equal(2, phishing.GetProperty("total").GetInt32());
        Assert.Equal(1, phishing.GetProperty("wrong").GetInt32());
        Assert.Equal(0, phishing.GetProperty("withEmail").GetInt32());
    }

    [Fact]
    public async Task Invalid_feedback_is_rejected()
    {
        var response = await Client(TempDb()).PostAsJsonAsync("/api/v1/feedback", new { correct = true, verdict = "'; DROP TABLE feedback; --", score = 1 });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("phishing", true, "phishing")]
    [InlineData("phishing", false, "legitimate")]
    [InlineData("safe", true, "legitimate")]
    [InlineData("safe", false, "phishing")]
    [InlineData("suspicious", false, null)]   // "wrong" doesn't say which way
    public void Feedback_implies_a_training_label_only_when_unambiguous(string verdict, bool correct, string? label) =>
        Assert.Equal(label, new FeedbackRequest { Verdict = verdict, Correct = correct }.ImpliedLabel());
}
