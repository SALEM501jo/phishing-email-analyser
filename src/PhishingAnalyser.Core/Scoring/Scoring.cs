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
}
