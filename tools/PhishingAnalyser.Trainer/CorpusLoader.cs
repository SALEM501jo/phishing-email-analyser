using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CsvHelper;
using CsvHelper.Configuration;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer;

public sealed record LabelledEmail(string Text, bool IsPhishing, string Corpus);

/// <summary>
/// Builds the training set from the "Phishing Email Curated Datasets" (Champa et al., Zenodo 10.5281/zenodo.8339691).
///   phishing   = Nazario + Nazario_5 (label 1)       - real phishing collected 2005-2022
///   legitimate = Nazario_5 (label 0) + SpamAssassin ham - raw Enron mail + mailing-list/personal mail
/// SpamAssassin *spam* is deliberately excluded: spam is not phishing, and mixing them would teach the
/// model "marketing = phishing". Enron.csv is excluded because it was pre-lowercased/tokenised, which the
/// model would learn to use as a shortcut.
/// </summary>
public static partial class CorpusLoader
{
    private static readonly (string File, int? OnlyLabel)[] Sources =
    [
        ("Nazario.csv", 1),
        ("Nazario_5.csv", null),
        ("SpamAssasin.csv", 0),
    ];

    // Tokens that identify WHICH corpus an email came from rather than whether it is phishing
    // (the Nazario honeypot mailbox, Enron internal names, SpamAssassin list footers).
    [GeneratedRegex(@"\b(jose|monkey\.org|monkey|enron|ect|hou|corp|spamassassin|sourceforge|exmh|razor|listinfo|mailman|zzzz|yyyy|jm|fork|xent|irish linux users)\b", RegexOptions.IgnoreCase)]
    private static partial Regex CorpusArtifacts();

    // Undecoded MIME encoded-words ("=?utf-8?B?...?=") only survive in the phishing dump, and the
    // "URL: http://... Date: ..." lines come from SpamAssassin's RSS digests - both are format leaks.
    [GeneratedRegex(@"=\?[\w-]+\?[BQbq]\?[^?\s]*\?=|^\s*(URL|Date):.*$", RegexOptions.Multiline)]
    private static partial Regex FormatArtifacts();

    public static List<LabelledEmail> Load(string dataDir, out Dictionary<string, (int Phishing, int Legit)> stats)
    {
        var seen = new HashSet<string>();
        var emails = new List<LabelledEmail>();
        stats = [];

        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            BadDataFound = null,
            MissingFieldFound = null,
        };

        foreach (var (file, onlyLabel) in Sources)
        {
            var path = Path.Combine(dataDir, file);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Missing {path}. Run tools/download-data.sh first.");

            int phishing = 0, legit = 0;
            using var reader = new StreamReader(path);
            using var csv = new CsvReader(reader, config);
            csv.Read();
            csv.ReadHeader();

            while (csv.Read())
            {
                if (!int.TryParse(csv.GetField("label"), out var label) || (onlyLabel is { } l && label != l))
                    continue;

                var subject = csv.GetField("subject");
                var body = csv.GetField("body");

                // Mailbox-format placeholder rows in the Nazario dump, not real emails.
                if (body?.Contains("internal format of your mail folder", StringComparison.OrdinalIgnoreCase) == true)
                    continue;

                var text = EmailTextNormalizer.Normalize(
                    FormatArtifacts().Replace(subject ?? "", " "),
                    FormatArtifacts().Replace(body ?? "", " "));
                text = CorpusArtifacts().Replace(text, " ");
                if (text.Length < 40)
                    continue;

                // Nazario_5 overlaps Nazario - dedupe on normalised text so the test set has no copies of training emails.
                if (!seen.Add(Hash(text)))
                    continue;

                emails.Add(new LabelledEmail(text, label == 1, file));
                if (label == 1) phishing++; else legit++;
            }

            stats[file] = (phishing, legit);
        }

        return emails;
    }

    private static string Hash(string text) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(text.ToLowerInvariant())));
}
