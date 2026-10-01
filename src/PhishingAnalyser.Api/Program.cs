using System.Diagnostics;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.HttpOverrides;
using OpenTelemetry.Metrics;
using PhishingAnalyser.Api;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;

// Small command-line utilities that share the binary (no web host is started for these).
if (args is ["--healthcheck", ..])
    return await HealthProbe(args.Length > 1 ? args[1] : "http://127.0.0.1:8080/health");
if (args is ["--new-api-key", var clientName])
{
    var (key, hash) = ApiClients.NewKey();
    Console.WriteLine($"Key for the extension (shown once, store it there): {key}");
    Console.WriteLine("Server settings (environment variables, N = next free index):");
    Console.WriteLine($"  ApiClients__N__Name={clientName}");
    Console.WriteLine($"  ApiClients__N__KeySha256={hash}");
    return 0;
}

// The models were trained on NFKC-folded text; refuse to serve rather than silently feed them different input.
if (!EmailTextNormalizer.NormalizationAvailable)
    throw new InvalidOperationException("Unicode normalization is unavailable (invariant globalization or no ICU) - " +
                                        "the text models would see different input than they were trained on.");

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 512 * 1024);

// Thresholds come from the model's calibration (model-info.json); anything under "Scoring" in config overrides them.
builder.Services.AddSingleton(sp =>
{
    var options = new ScoringOptions();
    if (sp.GetRequiredService<IContentClassifier>().Model?.Thresholds is { } calibrated)
    {
        options.PhishingThreshold = calibrated.Phishing;
        options.SuspiciousThreshold = calibrated.Suspicious;
    }
    builder.Configuration.GetSection("Scoring").Bind(options);
    return options;
});
builder.Services.AddSingleton(builder.Configuration["Brands:Path"] is { Length: > 0 } brandsPath
    ? BrandCatalog.Load(brandsPath)
    : BrandCatalog.Default);
builder.Services.AddSingleton<HeaderAnalyser>();
builder.Services.AddSingleton<LinkAnalyser>();
builder.Services.AddSingleton<IContentClassifier>(sp => LoadClassifier(sp, builder.Configuration, builder.Environment));

// Reputation: domain age (RDAP), public threat feeds, optional Google Safe Browsing - see ReputationOptions.
var reputationOptions = builder.Configuration.GetSection("Reputation").Get<ReputationOptions>() ?? new ReputationOptions();
builder.Services.AddSingleton(reputationOptions);
builder.Services.AddHttpClient("rdap", c => { c.Timeout = TimeSpan.FromSeconds(5); c.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json"); });
builder.Services.AddHttpClient("feeds", c => c.Timeout = TimeSpan.FromSeconds(60));
builder.Services.AddHttpClient("safebrowsing", c => c.Timeout = TimeSpan.FromSeconds(5));
// Short-link expansion: no auto-redirects + connect-time block of internal addresses (SSRF guard).
builder.Services.AddHttpClient("shortlinks", c => c.Timeout = TimeSpan.FromSeconds(3))
    .ConfigurePrimaryHttpMessageHandler(ShortLinkExpander.CreateSafeHandler);
builder.Services.AddSingleton(sp => new ShortLinkExpander(sp.GetRequiredService<IHttpClientFactory>().CreateClient("shortlinks")));
builder.Services.AddSingleton<ThreatFeedStore>();
builder.Services.AddHostedService<ThreatFeedRefresher>();
builder.Services.AddSingleton(sp =>
{
    var http = sp.GetRequiredService<IHttpClientFactory>();
    return new ReputationAnalyser(
        sp.GetRequiredService<BrandCatalog>(),
        reputationOptions,
        sp.GetRequiredService<ThreatFeedStore>(),
        reputationOptions.DomainAge ? new DomainAgeChecker(http.CreateClient("rdap")) : null,
        string.IsNullOrWhiteSpace(reputationOptions.SafeBrowsingApiKey) ? null : new SafeBrowsingClient(http.CreateClient("safebrowsing"), reputationOptions.SafeBrowsingApiKey));
});

builder.Services.AddSingleton(sp => new EmailAnalyser(
    sp.GetRequiredService<IContentClassifier>(),
    sp.GetRequiredService<HeaderAnalyser>(),
    sp.GetRequiredService<LinkAnalyser>(),
    sp.GetRequiredService<ScoringOptions>(),
    sp.GetRequiredService<ReputationAnalyser>(),
    reputationOptions.Enabled && builder.Configuration.GetValue("Reputation:ExpandShortLinks", true) ? sp.GetRequiredService<ShortLinkExpander>() : null));

// Feedback (👍/👎) in a small SQLite file - a Docker volume in production.
builder.Services.AddSingleton(sp =>
{
    var configured = builder.Configuration["Feedback:DatabasePath"] ?? "data/feedback.db";
    return new FeedbackStore(Path.IsPathRooted(configured) ? configured : Path.Combine(builder.Environment.ContentRootPath, configured));
});

// Per-client API keys (hashes in config); see ApiClients.
var apiClients = new ApiClients(
    builder.Configuration.GetSection("ApiClients").Get<List<ApiClientOptions>>() ?? [],
    builder.Configuration["ApiKey"]);
builder.Services.AddSingleton(apiClients);

// The reverse proxy's X-Forwarded-For is honoured only when the request comes from a configured proxy address.
// Behind Docker the proxy connects from the bridge gateway, not loopback - docker-compose.yml sets it.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
    o.ForwardLimit = 1; // only the address our own proxy appended; anything further left is client-controlled
    foreach (var proxy in builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [])
        o.KnownProxies.Add(IPAddress.Parse(proxy));
    foreach (var network in builder.Configuration.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>() ?? [])
        o.KnownNetworks.Add(ParseNetwork(network));
});

builder.Services.AddSingleton<Telemetry>();
builder.Services.AddOpenTelemetry().WithMetrics(m =>
{
    m.AddMeter(Telemetry.MeterName, "Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Server.Kestrel", "Microsoft.AspNetCore.RateLimiting")
     .AddView("phishing.analysis.duration", new ExplicitBucketHistogramConfiguration
     {
         Boundaries = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5], // seconds; the default buckets start at 5 s
     })
     .AddRuntimeInstrumentation()
     .AddPrometheusExporter();
    if (!string.IsNullOrEmpty(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
        m.AddOtlpExporter(); // optional push to an OpenTelemetry collector
});
var metricsPort = builder.Configuration.GetValue("Metrics:Port", 9464);

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    // One bucket per API client when keys are in use, otherwise per client IP (as reported by the trusted proxy).
    o.AddPolicy("analyse", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Items[ApiClients.ItemKey] is string client ? $"client:{client}" : $"ip:{ctx.Connection.RemoteIpAddress}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = builder.Configuration.GetValue("RateLimit:PerMinute", 60),
            Window = TimeSpan.FromMinutes(1),
        }));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseForwardedHeaders();
// Identify the API client before rate limiting, so the limiter can partition by client.
app.Use((ctx, next) =>
{
    if (apiClients.Enabled && apiClients.Identify(ctx.Request.Headers[ApiClients.HeaderName]) is { } client)
        ctx.Items[ApiClients.ItemKey] = client;
    return next(ctx);
});
app.UseRateLimiter();

// Prometheus metrics only on the internal port - docker-compose doesn't publish it to the proxy.
app.MapPrometheusScrapingEndpoint().RequireHost($"*:{metricsPort}");

// Warm the model at startup so the first request isn't slow and a broken model fails loudly in the logs.
var classifier = app.Services.GetRequiredService<IContentClassifier>();

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    contentModelLoaded = classifier.IsLoaded,
    model = classifier.Model,
    thresholds = new { app.Services.GetRequiredService<ScoringOptions>().PhishingThreshold, app.Services.GetRequiredService<ScoringOptions>().SuspiciousThreshold },
    threatFeeds = new { urls = app.Services.GetRequiredService<ThreatFeedStore>().UrlCount, loadedAt = app.Services.GetRequiredService<ThreatFeedStore>().LoadedAt },
}));

app.MapPost("/api/v1/analyse", async Task<Results<Ok<AnalysisResult>, ValidationProblem>> (
        AnalyseRequest request, EmailAnalyser analyser, Telemetry telemetry, HttpContext http, ILogger<Program> logger, CancellationToken ct) =>
    {
        if (request.Validate() is { Count: > 0 } errors)
            return TypedResults.ValidationProblem(errors);

        var started = Stopwatch.GetTimestamp();
        var result = await analyser.AnalyseAsync(request.ToSubmission(), ct);
        telemetry.Analysed(result, Stopwatch.GetElapsedTime(started));

        // Deliberately no email content in logs - only the outcome and which client asked.
        logger.LogInformation("Analysed email: client={Client} verdict={Verdict} score={Score} links={Links} rawHeaders={HasHeaders}",
            http.Items[ApiClients.ItemKey] ?? "-", result.Verdict, result.Score, request.Links?.Count ?? 0, !string.IsNullOrEmpty(request.RawHeaders));
        if (app.Environment.IsDevelopment())
        {
            // Local debugging only: registrable DOMAINS and rule codes (never text) to see why a trust rule did or didn't apply.
            var submission = request.ToSubmission();
            var linkDomains = (submission.Links ?? []).Select(l => PhishingAnalyser.Core.Rules.DomainUtils.GetHost(l.Href))
                .OfType<string>().Select(PhishingAnalyser.Core.Rules.DomainUtils.RegistrableDomain).Distinct();
            var codes = result.Breakdown.Headers.Findings.Concat(result.Breakdown.Links.Findings).Select(f => f.Code).Distinct();
            foreach (var l in (submission.Links ?? []).Where(l => PhishingAnalyser.Core.Rules.DomainUtils.GetHost(l.Href)?.EndsWith("google.com") == true).Take(3))
                if (PhishingAnalyser.Core.Rules.DomainUtils.TryCreateUri(l.Href, out var gu))
                    logger.LogInformation("[dev] google link host={Host} path={Path} params={Params}", gu.Host, gu.AbsolutePath,
                        string.Join(",", System.Web.HttpUtility.ParseQueryString(gu.Query).AllKeys));
            logger.LogInformation("[dev] sender={Sender} linkDomains={LinkDomains} codes={Codes}",
                PhishingAnalyser.Core.Rules.DomainUtils.GetEmailDomain(submission.SenderEmail), string.Join(",", linkDomains), string.Join(",", codes));
        }

        return TypedResults.Ok(result);
    })
    .AddEndpointFilter(RequireApiKey)
    .RequireRateLimiting("analyse")
    .WithName("AnalyseEmail");

app.MapPost("/api/v1/feedback", Results<NoContent, ValidationProblem> (FeedbackRequest request, FeedbackStore store, Telemetry telemetry, ILogger<Program> logger) =>
    {
        if (request.Validate() is { Count: > 0 } errors)
            return TypedResults.ValidationProblem(errors);
        store.Add(request);
        telemetry.Feedback(request.Verdict!, request.Correct);
        logger.LogInformation("Feedback: verdict={Verdict} correct={Correct} withEmail={WithEmail}", request.Verdict, request.Correct, request.Email is not null);
        return TypedResults.NoContent();
    })
    .AddEndpointFilter(RequireApiKey)
    .RequireRateLimiting("analyse")
    .WithName("SubmitFeedback");

// Error rates per verdict (counts only, no content).
app.MapGet("/api/v1/feedback/summary", (FeedbackStore store) => Results.Ok(store.Summary()))
    .AddEndpointFilter(RequireApiKey)
    .WithName("FeedbackSummary");

await app.RunAsync();
return 0;

static IContentClassifier LoadClassifier(IServiceProvider sp, IConfiguration config, IHostEnvironment env)
{
    var logger = sp.GetRequiredService<ILogger<Program>>();
    var configured = config["ContentModel:Path"] ?? "models/phishing-content-model.zip";
    var path = Path.IsPathRooted(configured) ? configured : Path.Combine(env.ContentRootPath, configured);

    var linear = File.Exists(path) ? ContentClassifier.Load(path) : null;

    // Preferred: the multilingual transformer decides, the linear model explains (strongest cue words).
    var transformerDir = config["ContentModel:TransformerPath"] ?? Path.Combine(Path.GetDirectoryName(path)!, "transformer");
    if (!Path.IsPathRooted(transformerDir))
        transformerDir = Path.Combine(env.ContentRootPath, transformerDir);
    if (File.Exists(Path.Combine(transformerDir, "model.onnx")))
    {
        logger.LogInformation("Loading multilingual transformer from {Path} (explanations from the linear model)", transformerDir);
        return new HybridContentClassifier(TransformerClassifier.Load(transformerDir), linear);
    }

    if (linear is null)
    {
        logger.LogWarning("No content model found at {Path}; running with rule-based checks only", path);
        return new UnavailableContentClassifier();
    }

    logger.LogInformation("Loading linear content model from {Path}", path);
    return linear;
}

// When any API keys are configured, the endpoint needs one (identified by the middleware above).
static async ValueTask<object?> RequireApiKey(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
{
    var http = ctx.HttpContext;
    if (!http.RequestServices.GetRequiredService<ApiClients>().Enabled || http.Items.ContainsKey(ApiClients.ItemKey))
        return await next(ctx);
    http.RequestServices.GetRequiredService<Telemetry>().RejectedKey();
    return Results.Unauthorized();
}

static Microsoft.AspNetCore.HttpOverrides.IPNetwork ParseNetwork(string cidr)
{
    var parts = cidr.Split('/', 2);
    var address = IPAddress.Parse(parts[0]);
    var prefix = parts.Length == 2 ? int.Parse(parts[1]) : address.GetAddressBytes().Length * 8;
    return new Microsoft.AspNetCore.HttpOverrides.IPNetwork(address, prefix);
}

// Docker HEALTHCHECK probe: the runtime image has no curl, so the API binary checks itself.
static async Task<int> HealthProbe(string url)
{
    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        using var response = await http.GetAsync(url);
        return response.IsSuccessStatusCode ? 0 : 1;
    }
    catch (Exception)
    {
        return 1;
    }
}

public partial class Program;
