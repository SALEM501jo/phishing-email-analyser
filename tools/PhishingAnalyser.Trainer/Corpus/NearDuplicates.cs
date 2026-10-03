using System.Text.RegularExpressions;

namespace PhishingAnalyser.Trainer.Corpus;

/// <summary>
/// Groups emails whose text is largely the same - one phishing campaign sent under many subjects - so the split keeps
/// each campaign on ONE side. The subject-only grouping let about 18% of test phishing have a near-copy in training,
/// which lifted the reported recall by about 5 points (evaluation audit; see NoveltyRecall).
///
/// MinHash over 5-word shingles (a fixed quarter of them, so long emails stay cheap), 16 bands of 4 rows: pairs with
/// a Jaccard similarity around 0.6 or more collide in some band with high probability. Shingles found in more than
/// <see cref="MaxDocumentFrequency"/> emails (list footers, disclaimers) are ignored, so shared boilerplate can't chain
/// unrelated emails into one giant group. Emails that share a subject group stay together as before.
/// </summary>
public static partial class NearDuplicates
{
    private const int ShingleWords = 5;
    private const int Bands = 16;
    private const int Rows = 4;
    private const int MaxDocumentFrequency = 50;
    private const int MinShingles = 3;

    [GeneratedRegex(@"\p{L}+")]
    private static partial Regex Word();

    public static List<CorpusEmail> Cluster(List<CorpusEmail> emails)
    {
        var shingles = emails.Select(e => Shingles(e.Text).Distinct().ToArray()).ToArray();
        var frequency = new Dictionary<ulong, int>();
        foreach (var set in shingles)
            foreach (var h in set)
                frequency[h] = frequency.GetValueOrDefault(h) + 1;

        var parent = Enumerable.Range(0, emails.Count).ToArray();
        int Find(int i)
        {
            while (parent[i] != i)
                i = parent[i] = parent[parent[i]];
            return i;
        }
        void Union(int a, int b)
        {
            (a, b) = (Find(a), Find(b));
            if (a != b)
                parent[Math.Max(a, b)] = Math.Min(a, b);
        }

        var bySubject = new Dictionary<string, int>();
        for (var i = 0; i < emails.Count; i++)
            if (bySubject.TryGetValue(emails[i].Group, out var first)) Union(i, first);
            else bySubject[emails[i].Group] = i;
        var subjectGroups = bySubject.Count;

        var seeds = Enumerable.Range(1, Bands * Rows).Select(k => Mix((ulong)k * 0x9E3779B97F4A7C15UL)).ToArray();
        var buckets = new Dictionary<(int Band, ulong Key), int>();
        var signature = new ulong[Bands * Rows];
        for (var i = 0; i < emails.Count; i++)
        {
            var features = shingles[i].Where(h => frequency[h] <= MaxDocumentFrequency).ToArray();
            if (features.Length < MinShingles)
                continue;
            Array.Fill(signature, ulong.MaxValue);
            foreach (var h in features)
                for (var k = 0; k < signature.Length; k++)
                    signature[k] = Math.Min(signature[k], Mix(h ^ seeds[k]));
            for (var band = 0; band < Bands; band++)
            {
                var key = 14695981039346656037UL;
                for (var r = 0; r < Rows; r++)
                    key = Mix(key ^ signature[band * Rows + r]);
                if (buckets.TryGetValue((band, key), out var other)) Union(i, other);
                else buckets[(band, key)] = i;
            }
        }

        // One key per connected group: the smallest subject key in it (deterministic).
        var groupKey = new Dictionary<int, string>();
        for (var i = 0; i < emails.Count; i++)
        {
            var root = Find(i);
            if (!groupKey.TryGetValue(root, out var key) || string.CompareOrdinal(emails[i].Group, key) < 0)
                groupKey[root] = emails[i].Group;
        }
        var sizes = Enumerable.Range(0, emails.Count).GroupBy(Find).Select(g => g.Count()).OrderDescending().ToList();
        Console.WriteLine($"  near-duplicate grouping: {subjectGroups} subject groups -> {groupKey.Count} campaign groups " +
                          $"(largest {sizes[0]}, next {string.Join(", ", sizes.Skip(1).Take(4))})");

        return emails.Select((e, i) => e with { Group = groupKey[Find(i)] }).ToList();
    }

    /// <summary>Hashes of every 5-word window, keeping a fixed quarter of them (the same quarter for every email).</summary>
    internal static IEnumerable<ulong> Shingles(string text, int words = ShingleWords, int keepOneIn = 4)
    {
        var tokens = Word().Matches(text.ToLowerInvariant()).Select(m => m.Value).ToArray();
        for (var i = 0; i + words <= tokens.Length; i++)
        {
            var hash = 14695981039346656037UL; // FNV-1a 64
            for (var w = i; w < i + words; w++)
            {
                foreach (var ch in tokens[w])
                    hash = (hash ^ ch) * 1099511628211UL;
                hash = (hash ^ ' ') * 1099511628211UL;
            }
            if (hash % (ulong)keepOneIn == 0)
                yield return hash;
        }
    }

    private static ulong Mix(ulong x) // SplitMix64 finaliser
    {
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9UL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBUL;
        return x ^ (x >> 31);
    }
}
