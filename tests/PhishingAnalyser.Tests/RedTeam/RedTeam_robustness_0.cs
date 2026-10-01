using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class RedTeam_robustness_0
{
    [Fact]
    public void Analyser_returns_a_verdict_for_links_that_make_Uri_TryCreate_throw()
    {
        // .NET 8's Uri.TryCreate THROWS IndexOutOfRangeException (instead of returning false) for an implicit-file/UNC URL whose
        // only host character is a bidi mark. DomainUtils.GetHost, LinkAnalyser.Unwrap and LinkAnalyser.IsNeutralLink call it unguarded.
        var analyser = new EmailAnalyser(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
            new LinkAnalyser(BrandCatalog.Default), new ScoringOptions { TrustVerifiedBrandSenders = true });
        var hrefs = new[]
        {
            "https://www.google.com/url?q=file://%E2%80%8F",                                     // pure ASCII; Unwrap decodes "file://<RLM>", GetHost throws
            "https://nam12.safelinks.protection.outlook.com/?url=file%3A%2F%2F%E2%80%8F&data=x",  // same through Outlook safelinks
            "//‏", "///‮", "\\\\‎", "file://‏",                              // Unwrap / IsNeutralLink throw directly
        };
        var failures = new List<string>();
        foreach (var href in hrefs)
        {
            var plain = new EmailSubmission
            {
                Subject = "Your invoice", Body = "Open the invoice below.", SenderEmail = "billing@example.com",
                Links = [new EmailLink("View invoice", href)],
            };
            var ex = Record.Exception(() => analyser.Analyse(plain));
            if (ex is not null)
                failures.Add($"plain mail, href '{Escape(href)}': {ex.GetType().Name} at {TopFrame(ex)}");

            var brand = new EmailSubmission
            {
                Subject = "Your receipt", Body = "Thanks for your purchase.", SenderEmail = "no_reply@email.apple.com",
                RawHeaders = "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\nFrom: Apple <no_reply@email.apple.com>\n",
                Links = [new EmailLink("View receipt", href)],
            };
            AnalysisResult? result = null;
            ex = Record.Exception(() => result = analyser.Analyse(brand));
            if (ex is not null)
                failures.Add($"brand mail, href '{Escape(href)}': {ex.GetType().Name} at {TopFrame(ex)}");
            else if (result!.Breakdown.Headers.Findings.Any(f => f.Code == "verified-brand-sender"))
                failures.Add($"brand mail, href '{Escape(href)}': verified-brand-sender granted (must fail closed)");
        }

        var direct = new (string Name, Action Call)[]
        {
            ("DomainUtils.GetHost(\"file://<RLM>\")", () => DomainUtils.GetHost("file://‏")),
            ("LinkAnalyser.Unwrap(\"//<RLM>\")", () => LinkAnalyser.Unwrap("//‏")),
            ("LinkAnalyser.IsNeutralLink(\"//<RLM>\")", () => LinkAnalyser.IsNeutralLink("//‏")),
        };
        foreach (var (name, call) in direct)
        {
            var ex = Record.Exception(call);
            if (ex is not null)
                failures.Add($"{name}: {ex.GetType().Name} at {TopFrame(ex)}");
        }

        Assert.True(failures.Count == 0, "Analysis crashed:\n" + string.Join("\n", failures));
    }

    private static string Escape(string s) =>
        string.Concat(s.Select(c => c < 0x20 || c > 0x7E ? $"\\u{(int)c:X4}" : c.ToString()));

    private static string TopFrame(Exception ex) =>
        string.Join(" <- ", (ex.StackTrace ?? "").Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("at ")).Where(l => l.Contains("PhishingAnalyser.Core")).Take(3)
            .Select(l => l[3..].Split(" in ")[0]));
}
