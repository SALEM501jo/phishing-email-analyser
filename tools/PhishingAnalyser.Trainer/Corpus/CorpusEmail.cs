using PhishingAnalyser.Core;

namespace PhishingAnalyser.Trainer.Corpus;

/// <param name="Text">Normalised, artifact-scrubbed text the classifier trains on.</param>
/// <param name="Class">One of EmailClasses.</param>
/// <param name="Source">Dataset it came from (for per-source reporting).</param>
/// <param name="Modern">True for 2022+ mail; used for the temporal-generalisation experiment.</param>
/// <param name="Group">Normalised subject - emails in the same thread/campaign land on the same side of the split.</param>
/// <param name="Submission">Full parsed email (sender, links, headers) when available, for end-to-end evaluation.</param>
/// <param name="NoisyLabel">Comes from a source labelled wholesale (honeypot / spam trap); eligible for confident-learning cleanup.</param>
public sealed record CorpusEmail(
    string Text,
    string Class,
    string Source,
    bool Modern,
    string Group,
    EmailSubmission? Submission,
    bool NoisyLabel = false,
    string Subject = "",
    string VisibleBody = "",
    string Language = "en");

public enum Split { Train, Tune, Test }
