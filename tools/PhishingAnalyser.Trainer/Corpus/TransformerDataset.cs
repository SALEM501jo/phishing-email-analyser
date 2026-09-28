using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer.Corpus;

/// <summary>A row exchanged with the Python scripts (translate / generate / train). Raw visible text, not yet normalised.</summary>
public sealed record ExchangeRow(
    string Id,
    string Subject,
    string Body,
    string Class,
    string Source,
    bool Modern,
    string Split,
    string Language = "en",
    bool LabelIssue = false,
    string? PairKey = null);

/// <summary>A normalised row the transformer trains on.</summary>
public sealed record TrainingRow(string Text, string Label, string Language, string Source, bool Modern);

/// <summary>
/// The .NET half of the transformer pipeline. Text normalisation happens ONLY here, so the Python training
/// code and the .NET inference code can never disagree about preprocessing:
///   --export-corpus        cleaned corpus (raw visible text + split + confident-learning flags) -> corpus.jsonl
///   (python) translate.py  corpus.jsonl -> corpus_ar.jsonl        generate_pairs.py -> generated.jsonl
///   --prepare-transformer  all of the above -> normalised transformer_{train,val,test}.jsonl
/// </summary>
public static class TransformerDataset
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // keep Arabic readable
    };

    public static void Export(IEnumerable<CorpusEmail> emails, ISet<CorpusEmail> labelIssues, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        using var writer = new StreamWriter(path, false, new UTF8Encoding(false));
        var count = 0;
        foreach (var e in emails)
        {
            var row = new ExchangeRow(StableId(e.Source + "|" + e.Text), e.Subject, e.VisibleBody, e.Class, e.Source, e.Modern,
                CorpusBuilder.SplitOf(e).ToString().ToLowerInvariant(), e.Language, labelIssues.Contains(e));
            writer.WriteLine(JsonSerializer.Serialize(row, Json));
            count++;
        }
        Console.WriteLine($"Exported {count} emails to {path}");
    }

    /// <summary>
    /// Merges the exported corpus, its Arabic translation and the generated pairs, normalises every text with
    /// <see cref="EmailTextNormalizer"/>, and writes one file per split. Rows flagged by confident learning are
    /// left out of training (but kept in val/test, which are never cleaned).
    /// </summary>
    public static void Prepare(string processedDir)
    {
        var inputs = new[] { "corpus.jsonl", "corpus_ar.jsonl", "generated.jsonl" }
            .Select(f => Path.Combine(processedDir, f))
            .Where(File.Exists)
            .ToList();
        Console.WriteLine("Preparing transformer data from: " + string.Join(", ", inputs.Select(Path.GetFileName)));

        var writers = new[] { "train", "val", "test" }.ToDictionary(s => s,
            s => new StreamWriter(Path.Combine(processedDir, $"transformer_{s}.jsonl"), false, new UTF8Encoding(false)));
        var counts = new Dictionary<(string Split, string Lang, string Label), int>();

        foreach (var file in inputs)
        {
            var generated = Path.GetFileName(file) == "generated.jsonl";
            foreach (var line in File.ReadLines(file))
            {
                var row = JsonSerializer.Deserialize<ExchangeRow>(line, Json)!;
                var split = generated ? GeneratedSplit(row) : row.Split == "tune" ? "val" : row.Split;
                if (split == "train" && row.LabelIssue)
                    continue;

                var text = EmailTextNormalizer.Normalize(row.Subject, row.Body);
                if (!generated)
                    text = TextCleaning.ScrubCorpusArtifacts(text);
                if (text.Length < 30)
                    continue;

                writers[split].WriteLine(JsonSerializer.Serialize(new TrainingRow(text, row.Class, row.Language, row.Source, row.Modern), Json));
                var key = (split, row.Language, row.Class);
                counts[key] = counts.GetValueOrDefault(key) + 1;
            }
        }

        foreach (var w in writers.Values) w.Dispose();
        foreach (var ((split, lang, label), n) in counts.OrderBy(kv => kv.Key))
            Console.WriteLine($"  {split,-5} {lang,-3} {label,-11} {n,7}");
    }

    /// <summary>Generated emails are split by pair key (brand|type|language), so both halves of a pair land together.</summary>
    private static string GeneratedSplit(ExchangeRow row)
    {
        var bucket = BitConverter.ToUInt32(SHA256.HashData(Encoding.UTF8.GetBytes(row.PairKey ?? row.Id)), 0) % 100;
        return bucket < 15 ? "test" : bucket < 25 ? "val" : "train";
    }

    private static string StableId(string key) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..16].ToLowerInvariant();
}
