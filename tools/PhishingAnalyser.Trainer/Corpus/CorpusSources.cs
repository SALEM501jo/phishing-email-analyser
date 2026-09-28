using System.Globalization;
using System.IO.Compression;
using System.Text.RegularExpressions;
using CsvHelper;
using CsvHelper.Configuration;
using MimeKit;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Trainer.Corpus;

/// <summary>A raw email before cleaning, from any source format.</summary>
public sealed record RawEmail(string? Subject, string? Body, EmailSubmission? Submission);

/// <summary>Readers for the three source formats: Zenodo CSVs, .eml files, and mbox archives.</summary>
public static partial class CorpusSources
{
    /// <summary>Rows of a "Phishing Email Curated Datasets" CSV with the given label (0/1).</summary>
    public static IEnumerable<RawEmail> Csv(string path, int label)
    {
        var config = new CsvConfiguration(CultureInfo.InvariantCulture) { BadDataFound = null, MissingFieldFound = null };
        using var reader = new StreamReader(path);
        using var csv = new CsvReader(reader, config);
        csv.Read();
        csv.ReadHeader();

        while (csv.Read())
        {
            if (!int.TryParse(csv.GetField("label"), out var l) || l != label)
                continue;
            var body = csv.GetField("body");
            // Mailbox-format placeholder rows in the Nazario dump, not real emails.
            if (body?.Contains("internal format of your mail folder", StringComparison.OrdinalIgnoreCase) == true)
                continue;
            yield return new RawEmail(csv.GetField("subject"), body, null);
        }
    }

    /// <summary>One RFC 5322 message per file (phishing_pot uses *.eml, the untroubled.org spam archive *.txt in year/month folders).</summary>
    public static IEnumerable<RawEmail> MessageFiles(string directory, string pattern = "*.eml")
    {
        foreach (var file in Directory.EnumerateFiles(directory, pattern, SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            MimeMessage message;
            try
            {
                message = MimeMessage.Load(file);
            }
            catch (FormatException)
            {
                continue;
            }
            yield return FromMime(message);
        }
    }

    public static IEnumerable<RawEmail> MboxGz(string path)
    {
        using var stream = new GZipStream(File.OpenRead(path), CompressionMode.Decompress);
        var parser = new MimeParser(stream, MimeFormat.Mbox);
        while (!parser.IsEndOfStream)
        {
            MimeMessage message;
            try
            {
                message = parser.ParseMessage();
            }
            catch (FormatException)
            {
                yield break;
            }
            yield return FromMime(message);
        }
    }

    [GeneratedRegex(@"<a\b[^>]*?\bhref\s*=\s*[""']([^""']+)[""'][^>]*>(.*?)</a\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex HtmlAnchor();

    [GeneratedRegex(@"https?://[^\s<>""')\]]+", RegexOptions.IgnoreCase)]
    private static partial Regex PlainUrl();

    [GeneratedRegex(@"<(script|style)\b[^>]*>.*?</\1\s*>|<[^>]+>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex Markup();

    /// <summary>
    /// Converts a MIME message into what the browser extension would send: visible text, links (text + href),
    /// sender, Reply-To, and the raw header block.
    /// </summary>
    private static RawEmail FromMime(MimeMessage message)
    {
        var html = message.HtmlBody;
        var text = message.TextBody ?? (html is null ? "" : System.Net.WebUtility.HtmlDecode(Markup().Replace(html, " ")));

        var links = new List<EmailLink>();
        if (html is not null)
        {
            foreach (Match m in HtmlAnchor().Matches(html))
                links.Add(new EmailLink(System.Net.WebUtility.HtmlDecode(Markup().Replace(m.Groups[2].Value, " ")).Trim(),
                                        System.Net.WebUtility.HtmlDecode(m.Groups[1].Value)));
        }
        else
        {
            foreach (Match m in PlainUrl().Matches(text))
                links.Add(new EmailLink(m.Value, m.Value));
        }

        var from = message.From.Mailboxes.FirstOrDefault();
        var submission = new EmailSubmission
        {
            Subject = message.Subject,
            SenderName = from?.Name,
            SenderEmail = from?.Address,
            ReplyTo = message.ReplyTo.Mailboxes.FirstOrDefault()?.Address,
            Body = text,
            Links = links.Take(300).ToList(),
            // HeaderList.ToString() is not the header text - rebuild "Field: value" lines explicitly.
            RawHeaders = string.Concat(message.Headers.Select(h => $"{h.Field}: {h.Value}\n")),
        };

        return new RawEmail(message.Subject, text, submission);
    }

    /// <summary>Is the text English enough to train on? (Other languages are kept for future multilingual work.)</summary>
    public static bool IsEnglish(string normalizedText) => LanguageHeuristics.IsLikelyEnglish(normalizedText, minWords: 12);
}
