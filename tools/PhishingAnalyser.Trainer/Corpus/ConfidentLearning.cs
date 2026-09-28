using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer.Corpus;

public sealed record LabelIssue(string Source, string GivenClass, string PredictedClass, int Count);

/// <summary>
/// Confident-learning style label cleaning (Northcutt et al., 2021 - the idea behind cleanlab).
///
/// The honeypot (phishing_pot) and the spam trap (untroubled.org) are labelled wholesale by where the mail
/// arrived, so the honeypot's "phishing" contains marketing and the spam trap's "spam" contains phishing/fraud.
/// Each noisy example is scored by a model that never saw it (k-fold, split by thread/campaign); examples whose
/// given label the out-of-fold model finds very unlikely - while confidently preferring another class - are
/// dropped from TRAINING. Test data is never cleaned, so reported numbers stay conservative.
/// </summary>
public static class ConfidentLearning
{
    public const double GivenLabelMax = 0.15;
    public const double OtherLabelMin = 0.60;

    public static (List<CorpusEmail> Kept, List<LabelIssue> Issues) Clean(
        IReadOnlyList<CorpusEmail> train, Func<IReadOnlyCollection<CorpusEmail>, ContentClassifier> fit, int folds = 3)
    {
        var flagged = new HashSet<CorpusEmail>(ReferenceEqualityComparer.Instance);
        var issues = new List<(string Source, string Given, string Predicted)>();

        for (var fold = 0; fold < folds; fold++)
        {
            bool InFold(CorpusEmail e) => e.NoisyLabel && CorpusBuilder.Fold(e, folds) == fold;

            Console.WriteLine($"  confident learning: fold {fold + 1}/{folds}");
            var classifier = fit(train.Where(e => !InFold(e)).ToList());

            foreach (var email in train.Where(InFold))
            {
                var probabilities = classifier.Probabilities(email.Text);
                var (bestClass, bestP) = probabilities.Where(kv => kv.Key != email.Class).MaxBy(kv => kv.Value);
                if (probabilities[email.Class] < GivenLabelMax && bestP >= OtherLabelMin)
                {
                    flagged.Add(email);
                    issues.Add((email.Source, email.Class, bestClass));
                }
            }
        }

        var summary = issues.GroupBy(i => i).Select(g => new LabelIssue(g.Key.Source, g.Key.Given, g.Key.Predicted, g.Count()))
            .OrderByDescending(i => i.Count).ToList();
        return (train.Where(e => !flagged.Contains(e)).ToList(), summary);
    }
}
