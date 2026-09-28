namespace PhishingAnalyser.Core;

/// <summary>A hyperlink as it appeared in the email: the visible text and the real destination.</summary>
public sealed record EmailLink(string? Text, string Href);

/// <summary>What the browser extension extracts from the open Gmail message.</summary>
public sealed class EmailSubmission
{
    public string? Subject { get; init; }
    public string? SenderName { get; init; }
    public string? SenderEmail { get; init; }
    public string? ReplyTo { get; init; }
    public string? Body { get; init; }
    public IReadOnlyList<EmailLink>? Links { get; init; }

    /// <summary>
    /// Optional raw RFC 5322 header block (from Gmail's "Show original").
    /// When present, SPF/DKIM/DMARC results and Reply-To are read from it.
    /// </summary>
    public string? RawHeaders { get; init; }
}

/// <summary>
/// A single piece of evidence. <see cref="Weight"/> is in [0,1] and is read as
/// "probability this signal alone indicates phishing"; 0 means informational.
/// </summary>
public sealed record Finding(string Source, string Code, string Message, double Weight);

public sealed record ComponentResult(
    string Name,
    double Score,
    bool Evaluated,
    IReadOnlyList<Finding> Findings);

/// <param name="Probability">Probability the text is phishing.</param>
/// <param name="SpamProbability">Probability it is bulk/marketing spam (reported, not counted as phishing).</param>
/// <param name="LanguageSupported">False when the text doesn't look English - the model wasn't trained on it.</param>
public sealed record ContentResult(
    bool Evaluated,
    double Probability,
    double SpamProbability,
    IReadOnlyList<string> IndicativeTerms,
    bool LanguageSupported = true)
{
    public static ContentResult NotEvaluated { get; } = new(false, 0, 0, []);
}

public sealed record AnalysisResult(
    string Verdict,
    double Score,
    IReadOnlyList<string> Reasons,
    AnalysisBreakdown Breakdown,
    IReadOnlyList<string> Limitations,
    string? ModelVersion = null);

public sealed record AnalysisBreakdown(
    ContentResult Content,
    ComponentResult Headers,
    ComponentResult Links);

public static class Verdicts
{
    public const string Phishing = "phishing";
    public const string Suspicious = "suspicious";
    public const string Safe = "safe";
}
