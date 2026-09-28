using System.Text.Json;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Tests;

/// <summary>
/// The transformer is trained in Python and served in .NET; if the two tokenise differently the model silently
/// sees garbage. parity.json (written at training time) holds the Python token ids and logits for real English
/// and Arabic test emails - .NET must reproduce the ids exactly and the logits to within float tolerance.
/// These tests are no-ops until a transformer has been trained (models/transformer/ absent).
/// </summary>
public class TransformerParityTests
{
    private static readonly string Dir = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "models", "transformer"));

    private sealed record Fixture(string Text, int[] InputIds, float[] Logits);

    private static List<Fixture>? Fixtures() =>
        File.Exists(Path.Combine(Dir, "parity.json"))
            ? JsonSerializer.Deserialize<List<Fixture>>(File.ReadAllText(Path.Combine(Dir, "parity.json")), ContentClassifier.JsonOptions)
            : null;

    [Fact]
    public void Dotnet_tokenisation_matches_python_exactly()
    {
        if (Fixtures() is not { } fixtures) return; // no transformer trained yet
        using var model = TransformerClassifier.Load(Dir);
        foreach (var f in fixtures)
            Assert.Equal(f.InputIds, model.Encode(f.Text));
    }

    [Fact]
    public void Dotnet_inference_matches_python_logits()
    {
        if (Fixtures() is not { } fixtures) return;
        using var model = TransformerClassifier.Load(Dir);
        foreach (var f in fixtures)
        {
            var logits = model.Logits(f.Text);
            for (var i = 0; i < logits.Length; i++)
                Assert.InRange(logits[i], f.Logits[i] - 1e-3f, f.Logits[i] + 1e-3f);
        }
    }
}
