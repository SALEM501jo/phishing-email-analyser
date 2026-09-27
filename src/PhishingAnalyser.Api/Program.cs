using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.HttpResults;
using PhishingAnalyser.Api;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 512 * 1024);

builder.Services.Configure<ScoringOptions>(builder.Configuration.GetSection("Scoring"));
builder.Services.AddSingleton(sp => sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ScoringOptions>>().Value);
builder.Services.AddSingleton(BrandCatalog.Default);
builder.Services.AddSingleton<HeaderAnalyser>();
builder.Services.AddSingleton<LinkAnalyser>();
builder.Services.AddSingleton<IContentClassifier>(sp => LoadClassifier(sp, builder.Configuration, builder.Environment));
builder.Services.AddSingleton<EmailAnalyser>();

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

app.MapGet("/health", () => Results.Ok(new { status = "ok", contentModelLoaded = classifier.IsLoaded }));

app.MapPost("/api/v1/analyse", Results<Ok<AnalysisResult>, ValidationProblem> (
        AnalyseRequest request, EmailAnalyser analyser, ILogger<Program> logger) =>
    {
        if (request.Validate() is { Count: > 0 } errors)
            return TypedResults.ValidationProblem(errors);

        var result = analyser.Analyse(request.ToSubmission());

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

    if (!File.Exists(path))
    {
        logger.LogWarning("Content model not found at {Path}; running with rule-based checks only", path);
        return new UnavailableContentClassifier();
    }

    logger.LogInformation("Loading content model from {Path}", path);
    return ContentClassifier.Load(path);
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
