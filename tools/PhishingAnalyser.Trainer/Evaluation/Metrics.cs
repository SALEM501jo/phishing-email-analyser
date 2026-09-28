namespace PhishingAnalyser.Trainer.Evaluation;

public sealed record BinaryMetrics(
    int Count, int Positives, double Precision, double Recall, double F1, double FalsePositiveRate, double Auc,
    int TruePositives, int FalsePositives, int TrueNegatives, int FalseNegatives)
{
    public override string ToString() =>
        $"n={Count} (pos {Positives})  precision={Precision:P1}  recall={Recall:P1}  F1={F1:P1}  FPR={FalsePositiveRate:P2}  AUC={Auc:F4}";
}

public static class Metrics
{
    public static BinaryMetrics Binary(IReadOnlyList<(bool Actual, double Score)> rows, double threshold)
    {
        int tp = 0, fp = 0, tn = 0, fn = 0;
        foreach (var (actual, score) in rows)
        {
            var predicted = score >= threshold;
            if (actual && predicted) tp++;
            else if (!actual && predicted) fp++;
            else if (!actual) tn++;
            else fn++;
        }

        double precision = tp + fp == 0 ? 0 : (double)tp / (tp + fp);
        double recall = tp + fn == 0 ? 0 : (double)tp / (tp + fn);
        double f1 = precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall);
        double fpr = fp + tn == 0 ? 0 : (double)fp / (fp + tn);
        return new BinaryMetrics(rows.Count, tp + fn, R(precision), R(recall), R(f1), R(fpr), R(Auc(rows)), tp, fp, tn, fn);
    }

    /// <summary>Area under the ROC curve = probability a random positive scores above a random negative (ties count half).</summary>
    public static double Auc(IReadOnlyList<(bool Actual, double Score)> rows)
    {
        var sorted = rows.OrderBy(r => r.Score).ToList();
        long positives = sorted.Count(r => r.Actual), negatives = sorted.Count - positives;
        if (positives == 0 || negatives == 0)
            return double.NaN;

        double rankSum = 0;
        for (var i = 0; i < sorted.Count;)
        {
            var j = i;
            while (j < sorted.Count && sorted[j].Score == sorted[i].Score) j++;
            var averageRank = (i + 1 + j) / 2.0; // 1-based average rank of the tie block
            for (var k = i; k < j; k++)
                if (sorted[k].Actual) rankSum += averageRank;
            i = j;
        }

        return (rankSum - positives * (positives + 1) / 2.0) / (positives * (double)negatives);
    }

    public static Dictionary<string, Dictionary<string, int>> Confusion(IEnumerable<(string Actual, string Predicted)> rows, IEnumerable<string> classes)
    {
        var labels = classes.ToList();
        var matrix = labels.ToDictionary(a => a, _ => labels.ToDictionary(p => p, _ => 0));
        foreach (var (actual, predicted) in rows)
            matrix[actual][predicted]++;
        return matrix;
    }

    public static void PrintConfusion(Dictionary<string, Dictionary<string, int>> matrix, string indent = "    ")
    {
        var labels = matrix.Keys.ToList();
        Console.WriteLine(indent + "actual \\ predicted".PadRight(20) + string.Concat(labels.Select(l => l.PadLeft(12))));
        foreach (var actual in labels)
            Console.WriteLine(indent + actual.PadRight(20) + string.Concat(labels.Select(p => matrix[actual][p].ToString().PadLeft(12))));
    }

    private static double R(double v) => double.IsNaN(v) ? v : Math.Round(v, 4);
}
