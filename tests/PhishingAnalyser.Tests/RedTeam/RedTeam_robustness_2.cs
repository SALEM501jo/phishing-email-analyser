using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class RedTeam_robustness_2
{
    [Fact]
    public void Analyser_returns_a_verdict_when_an_address_domain_breaks_the_public_suffix_parser()
    {
        // Nager's DomainParser.TryParse calls Uri.TryCreate, which throws IndexOutOfRangeException for "//<RLM>".
        // HasKnownTld guards TryParse; RegistrableDomain and PrivatePlatformSuffix don't.
        var analyser = new EmailAnalyser(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
            new LinkAnalyser(BrandCatalog.Default), new ScoringOptions());
        var replyTo = new EmailSubmission
        {
            Subject = "Invoice overdue", Body = "Please reply with the payment confirmation.", SenderName = "Billing",
            SenderEmail = "billing@example.com",
            RawHeaders = "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n" +
                         "From: Billing <billing@example.com>\r\nReply-To: Accounts <x@//‏>\r\n",
        };
        var ex = Record.Exception(() => analyser.Analyse(replyTo));
        Assert.True(ex is null, $"Reply-To <x@//U+200F>: {ex?.GetType().Name} {ex?.StackTrace}");

        var sender = new EmailSubmission { Subject = "Invoice", Body = "Pay today.", SenderEmail = "x@\\\\‏" };
        ex = Record.Exception(() => analyser.Analyse(sender));
        Assert.True(ex is null, $"sender x@\\\\U+200F: {ex?.GetType().Name} {ex?.StackTrace}");

        Assert.Null(Record.Exception(() => DomainUtils.RegistrableDomain("//‏")));
        Assert.Null(Record.Exception(() => DomainUtils.PrivatePlatformSuffix("//‏")));
    }

    // Diagnostics: the same claim split per call site, so each part is checked on its own.
    [Fact]
    public void Diag_sender_address_alone()
    {
        var analyser = new EmailAnalyser(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
            new LinkAnalyser(BrandCatalog.Default), new ScoringOptions());
        var sender = new EmailSubmission { Subject = "Invoice", Body = "Pay today.", SenderEmail = "x@\\\\‏" };
        var ex = Record.Exception(() => analyser.Analyse(sender));
        Assert.True(ex is null, $"sender x@\\\\U+200F: {ex?.GetType().Name} {ex?.StackTrace}");
    }

    [Fact]
    public void Diag_registrable_domain_direct()
    {
        var ex = Record.Exception(() => DomainUtils.RegistrableDomain("//‏"));
        Assert.True(ex is null, $"RegistrableDomain: {ex?.GetType().Name}");
    }

    [Fact]
    public void Diag_private_platform_suffix_direct()
    {
        var ex = Record.Exception(() => DomainUtils.PrivatePlatformSuffix("//‏"));
        Assert.True(ex is null, $"PrivatePlatformSuffix: {ex?.GetType().Name}");
    }
}
