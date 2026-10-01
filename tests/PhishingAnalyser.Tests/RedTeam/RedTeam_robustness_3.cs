using System.Globalization;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class RedTeam_robustness_3
{
    [Fact]
    public void Analyser_returns_a_verdict_for_text_with_invalid_unicode_code_points()
    {
        // string.Normalize(FormKC) throws ArgumentException for U+FFFE and unpaired surrogates under ICU/NLS globalization
        // (the test host's default; the API itself runs invariant).
        var analyser = new EmailAnalyser(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
            new LinkAnalyser(BrandCatalog.Default), new ScoringOptions());
        foreach (var body in new[] { "Verify your account￾ today", "Verify your account\uD800 today" })
        {
            var email = new EmailSubmission { Subject = "Account notice", Body = body, SenderEmail = "alerts@example.com" };
            var ex = Record.Exception(() => analyser.Analyse(email));
            Assert.True(ex is null, $"body U+{(int)body[19]:X4}: {ex?.GetType().Name}: {ex?.Message}\n{ex?.StackTrace}");
            Assert.Null(Record.Exception(() => EmailTextNormalizer.Normalize("Notice￾", body)));
        }
    }
}
