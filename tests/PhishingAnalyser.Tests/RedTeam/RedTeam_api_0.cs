using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace PhishingAnalyser.Tests;

/// <summary>Red-team: the HTTP API as reached over the network (and as fed by the extension).</summary>
public class RedTeam_api_0(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private static string TempDb() => Path.Combine(Path.GetTempPath(), $"rt-feedback-{Guid.NewGuid():N}.db");

    private WebApplicationFactory<Program> App(int perMinute = 60, string? db = null) => factory.WithWebHostBuilder(b => b
        .UseSetting("Reputation:Enabled", "false")              // no network lookups in these tests
        // Rules only: these tests exercise the HTTP layer, and every host that loads the models costs ~500 MB.
        .UseSetting("ContentModel:Path", "no-model.zip").UseSetting("ContentModel:TransformerPath", "no-transformer")
        .UseSetting("Feedback:DatabasePath", db ?? TempDb())
        .UseSetting("RateLimit:PerMinute", perMinute.ToString())
        // Same proxy setup as docker-compose.yml: the host's reverse proxy reaches the container from the bridge gateway.
        .UseSetting("ForwardedHeaders:KnownProxies:0", "172.30.57.1")
        .ConfigureServices(s => s.AddSingleton<IStartupFilter>(new FromProxy(IPAddress.Parse("172.30.57.1")))));

    /// <summary>Every request arrives from the reverse proxy's address (as in production), before UseForwardedHeaders runs.</summary>
    private sealed class FromProxy(IPAddress proxy) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((ctx, n) => { ctx.Connection.RemoteIpAddress = proxy; return n(ctx); });
            next(app);
        };
    }

    [Fact]
    public void Feedback_store_stops_accepting_votes_at_its_size_cap()
    {
        var store = new PhishingAnalyser.Api.FeedbackStore(TempDb(), maxBytes: 1); // the empty database is already larger
        Assert.False(store.Add(new PhishingAnalyser.Api.FeedbackRequest { Correct = true, Verdict = "safe" }));
    }

    // ---- 1. Attachment names are cut at 255 chars by the API, which cuts off the file extension ----------------------

    [Fact]
    public async Task Long_attachment_name_still_flagged_as_html_attachment()
    {
        var client = App().CreateClient();
        // 270-char name: the user downloads "Remittance_Advice_000...000.html" (browsers keep the extension when they shorten a
        // long name); the API keeps only the first 255 chars, so the analyser sees no extension at all.
        var name = "Remittance_Advice_" + new string('0', 247) + ".html";
        Assert.Equal(270, name.Length);

        async Task<string[]> Codes(string attachment)
        {
            var response = await client.PostAsJsonAsync("/api/v1/analyse", new
            {
                subject = "Payment remittance", senderEmail = "accounts@vendor-billing.example", body = "Please see the attached remittance advice.",
                attachments = new[] { new { name = attachment, mimeType = "text/html" } },
            });
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadFromJsonAsync<JsonElement>();
            return json.GetProperty("breakdown").GetProperty("attachments").GetProperty("findings").EnumerateArray()
                .Select(f => f.GetProperty("code").GetString()!).ToArray();
        }

        Assert.Contains("html-attachment", await Codes("Remittance_Advice.html"));   // control: short name is flagged
        Assert.Contains("html-attachment", await Codes(name));                        // FAILS: the long name is not
    }

    // ---- 2. Rate limit partitions IPv6 clients per /128: one /64 = 2^64 independent buckets ----------------------------

    [Fact]
    public async Task Rate_limit_cannot_be_bypassed_by_rotating_addresses_inside_one_IPv6_64()
    {
        var client = App(perMinute: 1).CreateClient();
        async Task<HttpStatusCode> From(string clientIp)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/analyse") { Content = JsonContent.Create(new { subject = "hello" }) };
            request.Headers.Add("X-Forwarded-For", clientIp);   // appended by the trusted reverse proxy
            return (await client.SendAsync(request)).StatusCode;
        }

        // Control: the same address is limited.
        var same = new[] { await From("2001:db8:77:1::1"), await From("2001:db8:77:1::1"), await From("2001:db8:77:1::1") };
        Assert.Contains(HttpStatusCode.TooManyRequests, same);

        // One attacker host, one /64 (what any VPS or home connection gets), a fresh source address per request.
        var rotated = new List<HttpStatusCode>();
        for (var i = 1; i <= 20; i++)
            rotated.Add(await From($"2001:db8:66:1::{i:x}"));
        Assert.True(rotated.Count(s => s == HttpStatusCode.OK) <= 2,
            $"limit is 1/min, but {rotated.Count(s => s == HttpStatusCode.OK)} of 20 requests from one /64 were served");
    }

    // ---- 3. Feedback: most fields are unbounded, so one row can store ~the whole 512 KB request ------------------------

    [Fact]
    public async Task Feedback_rejects_oversized_fields_that_validation_does_not_cover()
    {
        var db = TempDb();
        var client = App(db: db).CreateClient();
        var big = new string('A', 120_000);   // 4 x 120 KB: the whole request stays under Kestrel's 512 KB cap

        var response = await client.PostAsJsonAsync("/api/v1/feedback", new
        {
            correct = true, verdict = "safe", score = 0.1,
            modelVersion = big,                                                    // unbounded
            email = new { subject = "s", senderEmail = big, body = "b",           // senderEmail unbounded
                          links = new[] { new { text = big, href = big } } },      // link text/href unbounded
        });

        var dbBytes = new FileInfo(db).Length;
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest,
            $"expected 400, got {(int)response.StatusCode}; feedback.db is now {dbBytes:N0} bytes after ONE vote (email body cap is 20,000 chars)");
    }

    [Fact]
    public async Task Feedback_summary_is_rate_limited_like_the_other_endpoints()
    {
        var client = App(perMinute: 1).CreateClient();
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
            statuses.Add((await client.GetAsync("/api/v1/feedback/summary")).StatusCode);   // full-table GROUP BY each time
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
    }

    [Theory]
    [InlineData("/api/v1/analyse", """{"subject":"x","links":[null]}""")]
    [InlineData("/api/v1/analyse", """{"subject":"x","attachments":[null]}""")]
    [InlineData("/api/v1/analyse", """{"subject":"x","qrCodeUrls":[null]}""")]
    [InlineData("/api/v1/feedback", """{"correct":true,"verdict":"safe","score":0,"reasonCodes":[null]}""")]
    public async Task Null_list_elements_are_a_400_not_an_unhandled_exception(string path, string json)
    {
        var client = App().CreateClient();
        var response = await client.PostAsync(path, new StringContent(json, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- 4. "Internal" metrics port is selected by the client-supplied Host header, not the port the request came in on --

    [Fact]
    public async Task Metrics_are_not_reachable_through_the_public_port_with_a_forged_Host_header()
    {
        var apiDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "PhishingAnalyser.Api", "bin", "Release", "net8.0"));
        var dll = Path.Combine(apiDir, "PhishingAnalyser.Api.dll");
        Assert.True(File.Exists(dll), $"build the API first: {dll}");

        int FreePort() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); var p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
        var publicPort = FreePort();
        var metricsPort = FreePort();

        var psi = new ProcessStartInfo("dotnet", $"\"{dll}\"")
        {
            WorkingDirectory = apiDir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        // Real Kestrel, two listeners - like the Docker image (ASPNETCORE_HTTP_PORTS="8080;9464"), loopback only here.
        psi.Environment["ASPNETCORE_URLS"] = $"http://127.0.0.1:{publicPort};http://127.0.0.1:{metricsPort}";
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
        psi.Environment["AllowAnonymous"] = "true";
        psi.Environment["ContentModel__TransformerPath"] = Path.Combine(Path.GetTempPath(), "no-transformer");
        psi.Environment["Metrics__Port"] = metricsPort.ToString();
        psi.Environment["Reputation__Enabled"] = "false";
        psi.Environment["Feedback__DatabasePath"] = TempDb();
        psi.Environment["ContentModel__Path"] = Path.Combine(Path.GetTempPath(), "no-model.zip");

        using var process = Process.Start(psi)!;
        process.OutputDataReceived += (_, _) => { };
        process.ErrorDataReceived += (_, _) => { };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            for (var i = 0; ; i++)
            {
                try { if ((await http.GetAsync($"http://127.0.0.1:{publicPort}/health")).IsSuccessStatusCode) break; }
                catch (HttpRequestException) { }
                Assert.True(i < 120, "API did not start");
                await Task.Delay(250);
            }

            // Sanity: the internal listener serves metrics, the public one doesn't for a normal request.
            Assert.Equal(HttpStatusCode.OK, (await http.GetAsync($"http://127.0.0.1:{metricsPort}/metrics")).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"http://127.0.0.1:{publicPort}/metrics")).StatusCode);

            await http.PostAsJsonAsync($"http://127.0.0.1:{publicPort}/api/v1/analyse", new { subject = "hello" });

            // Attack: a request on the PUBLIC listener (what the reverse proxy forwards; Caddy passes Host through unchanged)
            // whose Host header names the metrics port.
            using var forged = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{publicPort}/metrics");
            forged.Headers.Host = $"phishing.example.com:{metricsPort}";
            var response = await http.SendAsync(forged);
            var body = await response.Content.ReadAsStringAsync();
            Assert.True(response.StatusCode == HttpStatusCode.NotFound,
                $"public port served /metrics ({(int)response.StatusCode}, {body.Length} bytes), e.g.: " +
                string.Join(" | ", body.Split('\n').Where(l => !l.StartsWith('#') && (l.Contains("phishing") || l.Contains("http_server"))).Take(4)));
        }
        finally
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
        }
    }
}
