using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.HttpResults;
using PhishingAnalyser.Api;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Reputation;
using PhishingAnalyser.Core.Rules;

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

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("analyse", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
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

app.UseForwardedHeaders(new() { ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor });
app.UseRateLimiter();

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
        AnalyseRequest request, EmailAnalyser analyser, ILogger<Program> logger, CancellationToken ct) =>
    {
        if (request.Validate() is { Count: > 0 } errors)
            return TypedResults.ValidationProblem(errors);

        var result = await analyser.AnalyseAsync(request.ToSubmission(), ct);

        // Deliberately no email content in logs - only the outcome.
        logger.LogInformation("Analysed email: verdict={Verdict} score={Score} links={Links} rawHeaders={HasHeaders}",
            result.Verdict, result.Score, request.Links?.Count ?? 0, !string.IsNullOrEmpty(request.RawHeaders));

        return TypedResults.Ok(result);
    })
    .AddEndpointFilter(RequireApiKey(app.Configuration["ApiKey"]))
    .RequireRateLimiting("analyse")
    .WithName("AnalyseEmail");

app.Run();

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

// Optional shared-secret check so a publicly reachable demo instance isn't an open endpoint.
static Func<EndpointFilterInvocationContext, EndpointFilterDelegate, ValueTask<object?>> RequireApiKey(string? apiKey) =>
    async (ctx, next) =>
    {
        if (string.IsNullOrEmpty(apiKey))
            return await next(ctx);

        var supplied = ctx.HttpContext.Request.Headers["X-Api-Key"].ToString();
        var ok = CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(supplied), Encoding.UTF8.GetBytes(apiKey));
        return ok ? await next(ctx) : Results.Unauthorized();
    };

public partial class Program;
