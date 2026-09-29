using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Tests;

public class LanguageHeuristicsTests
{
    [Fact]
    public void English_text_is_recognised() =>
        Assert.True(LanguageHeuristics.IsLikelyEnglish(
            "Please verify your account within 24 hours or it will be suspended. Click the link below to continue."));

    [Theory]
    [InlineData("Prezado cliente, sua conta foi suspensa. Clique no link abaixo para atualizar seus dados cadastrais imediatamente para evitar o bloqueio.")]
    [InlineData("عزيزي العميل، تم تعليق حسابك مؤقتا. يرجى الضغط على الرابط أدناه لتحديث بياناتك خلال ٢٤ ساعة لتجنب إغلاق الحساب نهائيا")]
    public void Other_languages_are_not(string text) =>
        Assert.False(LanguageHeuristics.IsLikelyEnglish(text));

    [Fact]
    public void Very_short_text_gets_the_benefit_of_the_doubt() =>
        Assert.True(LanguageHeuristics.IsLikelyEnglish("Obrigado!"));
}

public class EmailTextNormalizerTests
{
    [Fact]
    public void Zero_width_characters_cannot_split_words() =>
        Assert.Contains("password", EmailTextNormalizer.Normalize(null, "Confirm your pa​ss‍word now"));

    [Fact]
    public void Urls_emails_and_digits_become_placeholders()
    {
        var text = EmailTextNormalizer.Normalize("Pay 24 hours", "Visit https://x.test/a or mail me@x.test");
        Assert.Contains("urltoken", text);
        Assert.Contains("emailtoken", text);
        Assert.Contains("numtoken", text);
        Assert.DoesNotContain("24", text);
    }

    [Fact]
    public void Html_is_stripped() =>
        Assert.Equal("Hello world", EmailTextNormalizer.Normalize(null, "<p>Hello <b>world</b></p><script>evil()</script>"));
}

public class ContentEvidenceTests
{
    private static readonly ScoringOptions Options = new();

    [Fact]
    public void Non_english_text_counts_half() =>
        Assert.Equal(Options.ContentWeight * 0.5 * 0.8,
            EmailAnalyser.ContentEvidence(new ContentResult(true, 0.8, 0, [], LanguageSupported: false), Options), 6);

    [Fact]
    public void Not_evaluated_counts_zero() =>
        Assert.Equal(0, EmailAnalyser.ContentEvidence(ContentResult.NotEvaluated, Options));

    [Fact]
    public void Preview_language_wording_alone_cannot_make_a_phishing_verdict()
    {
        // A preview-language model that is certain the Arabic text is phishing, and nothing else suspicious.
        var classifier = new FixedClassifier(new ContentResult(true, 1.0, 0, [], LanguageSupported: false, Language: "ar", LanguagePreview: true));
        var analyser = new EmailAnalyser(classifier, new PhishingAnalyser.Core.Rules.HeaderAnalyser(PhishingAnalyser.Core.Rules.BrandCatalog.Default),
            new PhishingAnalyser.Core.Rules.LinkAnalyser(PhishingAnalyser.Core.Rules.BrandCatalog.Default), Options);

        var result = analyser.Analyse(new EmailSubmission { Subject = "تم شحن طلبك", Body = "طلبك في الطريق ومن المتوقع وصوله يوم الخميس." });

        Assert.NotEqual(Verdicts.Phishing, result.Verdict);
        Assert.Contains(result.Limitations, l => l.Contains("تجريبية")); // the Arabic "preview" note, not "not trained"
        Assert.DoesNotContain(result.Limitations, l => l.Contains("لم يُدرَّب"));
    }

    private sealed class FixedClassifier(ContentResult result) : IContentClassifier
    {
        public bool IsLoaded => true;
        public ModelInfo? Model => null;
        public ContentResult Classify(string? subject, string? body) => result;
    }
}
