namespace PhishingAnalyser.Core;

public static class Scoring
{
    /// <summary>
    /// Combines independent pieces of evidence: 1 - Π(1 - wᵢ).
    /// One strong signal is enough to score high, weak signals accumulate, and the result stays in [0,1].
    /// </summary>
    public static double NoisyOr(IEnumerable<double> weights) =>
        1 - weights.Aggregate(1.0, (acc, w) => acc * (1 - Math.Clamp(w, 0, 1)));

    public static double NoisyOr(IEnumerable<Finding> findings) => NoisyOr(findings.Select(f => f.Weight));
}

public sealed class ScoringOptions
{
    /// <summary>
    /// How far the classifier alone can move the score. Below 1 so that text alone never
    /// produces absolute certainty; rule hits push it the rest of the way.
    /// </summary>
    public double ContentWeight { get; set; } = 0.9;

    public double PhishingThreshold { get; set; } = 0.7;
    public double SuspiciousThreshold { get; set; } = 0.4;

    /// <summary>
    /// Text alone can warn ("suspicious") but not convict: without any sender, link, attachment, obfuscation or
    /// reputation evidence, the text's contribution is capped just below the phishing threshold. A fake receipt and
    /// a real one read almost the same - what differs is who sent it and where its links go.
    /// </summary>
    public bool RequireCorroboration { get; set; }

    /// <summary>
    /// Mail proven to come from a catalogued brand's own domain (SPF+DKIM+DMARC pass, the header rule
    /// "verified-brand-sender") with no other warning sign gets its text evidence multiplied by
    /// <see cref="VerifiedBrandContentFactor"/>. Deliberately narrow: 31% of real phishing passes DMARC for the
    /// attacker's OWN domain, so authentication alone is never trusted - only a brand domain an attacker can't send from.
    /// </summary>
    public bool TrustVerifiedBrandSenders { get; set; }

    public double VerifiedBrandContentFactor { get; set; } = 0.2;
}
