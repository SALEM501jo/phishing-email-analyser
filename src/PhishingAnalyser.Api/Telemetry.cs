using System.Diagnostics;
using System.Diagnostics.Metrics;
using PhishingAnalyser.Core;

namespace PhishingAnalyser.Api;

/// <summary>
/// Application metrics (OpenTelemetry, scraped by Prometheus on the internal metrics port).
/// Counts and timings only - never email content, sender addresses or client keys.
/// </summary>
public sealed class Telemetry : IDisposable
{
    public const string MeterName = "PhishingAnalyser";

    private readonly Meter _meter = new(MeterName);
    private readonly Counter<long> _analyses;
    private readonly Histogram<double> _duration;
    private readonly Counter<long> _feedback;
    private readonly Counter<long> _rejectedKeys;

    public Telemetry()
    {
        _analyses = _meter.CreateCounter<long>("phishing.analyses", "{email}", "Emails analysed, by verdict and language");
        _duration = _meter.CreateHistogram<double>("phishing.analysis.duration", "s", "Time to analyse one email, including reputation lookups");
        _feedback = _meter.CreateCounter<long>("phishing.feedback", "{vote}", "User feedback on verdicts");
        _rejectedKeys = _meter.CreateCounter<long>("phishing.auth.rejected", "{request}", "Requests rejected for a missing or unknown API key");
    }

    public void Analysed(AnalysisResult result, TimeSpan elapsed)
    {
        var tags = new TagList { { "verdict", result.Verdict }, { "language", result.Language } };
        _analyses.Add(1, tags);
        _duration.Record(elapsed.TotalSeconds, tags);
    }

    public void Feedback(string verdict, bool correct) =>
        _feedback.Add(1, new TagList { { "verdict", verdict }, { "correct", correct } });

    public void RejectedKey() => _rejectedKeys.Add(1);

    public void Dispose() => _meter.Dispose();
}
