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

        // Damped Newton on the log-loss plus a weak prior pulling (A, B) towards the identity (1, 0).
        // Plain Newton diverges when the model is very confident (probabilities at ~0/1 make the data almost
        // separable): the first transformer fit ran off to A = 1.8e10. Each step must lower the loss or it is halved.
        const double Prior = 1.0;
        double Loss(double a, double b)
        {
            double loss = Prior / 2 * ((a - 1) * (a - 1) + b * b);
            for (var i = 0; i < x.Length; i++)
            {
                var z = a * x[i] + b;
                // log(1 + e^z) - t·z, computed stably
                loss += (z > 0 ? z + Math.Log(1 + Math.Exp(-z)) : Math.Log(1 + Math.Exp(z))) - t[i] * z;
            }
            return loss;
        }

        double a = 1, b = 0, current = Loss(a, b);
        for (var iteration = 0; iteration < 100; iteration++)
        {
            double ga = Prior * (a - 1), gb = Prior * b, haa = Prior, hab = 0, hbb = Prior;
            for (var i = 0; i < x.Length; i++)
            {
                var p = 1 / (1 + Math.Exp(-(a * x[i] + b)));
                var d = p - t[i];
                var w = p * (1 - p);
                ga += d * x[i]; gb += d;
                haa += w * x[i] * x[i]; hab += w * x[i]; hbb += w;
            }

            var det = haa * hbb - hab * hab;
            var da = (hbb * ga - hab * gb) / det;
            var db = (haa * gb - hab * ga) / det;
            var step = 1.0;
            while (step > 1e-6 && Loss(a - step * da, b - step * db) > current)
                step /= 2;
            if (step <= 1e-6)
                break;
            a -= step * da; b -= step * db;
            var next = Loss(a, b);
            var converged = current - next < 1e-9 * Math.Max(1, Math.Abs(current));
            current = next;
            if (converged)
                break;
        }

        // Never ship a calibration that makes probabilities worse than leaving them alone.
        var fitted = new PlattCalibration(Math.Round(a, 5), Math.Round(b, 5));
        var identity = new PlattCalibration(1, 0);
        return Brier(rows.Select(r => (fitted.Apply(r.Raw), r.Positive))) <= Brier(rows) ? fitted : identity;
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
