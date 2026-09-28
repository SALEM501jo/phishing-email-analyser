using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer.Evaluation;

/// <summary>
/// Platt scaling: fits calibrated = sigmoid(A·logit(raw) + B) by Newton's method on held-out data.
/// A class-imbalanced multiclass model produces probabilities that rank well (high AUC) but are
/// systematically too low for the minority class; this rescales them so "0.8" really means ~80%.
/// Uses Platt's smoothed targets to avoid over-confident fits on small sets.
/// </summary>
public static class Calibration
{
    public static PlattCalibration FitPlatt(IReadOnlyList<(double Raw, bool Positive)> rows)
    {
        double positives = rows.Count(r => r.Positive), negatives = rows.Count - positives;
        double hi = (positives + 1) / (positives + 2), lo = 1 / (negatives + 2);
        var x = rows.Select(r => Logit(r.Raw)).ToArray();
        var t = rows.Select(r => r.Positive ? hi : lo).ToArray();

        double a = 1, b = 0;
        for (var iteration = 0; iteration < 100; iteration++)
        {
            double ga = 0, gb = 0, haa = 0, hab = 0, hbb = 0;
            for (var i = 0; i < x.Length; i++)
            {
                var p = 1 / (1 + Math.Exp(-(a * x[i] + b)));
                var d = p - t[i];
                var w = p * (1 - p) + 1e-12;
                ga += d * x[i]; gb += d;
                haa += w * x[i] * x[i]; hab += w * x[i]; hbb += w;
            }

            haa += 1e-9; hbb += 1e-9; // keep the Hessian invertible
            var det = haa * hbb - hab * hab;
            var da = (hbb * ga - hab * gb) / det;
            var db = (haa * gb - hab * ga) / det;
            a -= da; b -= db;
            if (Math.Abs(da) < 1e-7 && Math.Abs(db) < 1e-7)
                break;
        }

        return new PlattCalibration(Math.Round(a, 5), Math.Round(b, 5));
    }

    /// <summary>Mean squared error between probability and outcome - lower is better calibrated.</summary>
    public static double Brier(IEnumerable<(double P, bool Positive)> rows) =>
        Math.Round(rows.Average(r => Math.Pow(r.P - (r.Positive ? 1 : 0), 2)), 5);

    private static double Logit(double p)
    {
        p = Math.Clamp(p, 1e-6, 1 - 1e-6);
        return Math.Log(p / (1 - p));
    }
}
