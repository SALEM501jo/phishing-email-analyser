using System.Diagnostics;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

/// <summary>Red-team finding: a crafted body made the password-archive regex backtrack quadratically (10 s per .zip).</summary>
[Collection(TimingSensitive.Name)]
public class RedTeam_robustness_1
{
    private static readonly EmailAnalyser Analyser = new(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
        new LinkAnalyser(BrandCatalog.Default), new ScoringOptions());

    private static TimeSpan Time(EmailSubmission email)
    {
        var stopwatch = Stopwatch.StartNew();
        Assert.NotNull(Analyser.Analyse(email).Verdict);
        return stopwatch.Elapsed;
    }

    [Fact]
    public void Password_archive_check_stays_fast_on_a_long_whitespace_run()
    {
        // "pwd" + 59,997 spaces = the extension's 60,000-character body cap; three archives (the regex used to run per archive).
        var elapsed = Time(new EmailSubmission
        {
            Subject = "Invoice", SenderEmail = "billing@example.com", Body = "pwd" + new string(' ', 59_997),
            Attachments = [new EmailAttachment("a.zip"), new EmailAttachment("b.zip"), new EmailAttachment("c.rar")],
        });
        Assert.True(elapsed < TimeSpan.FromSeconds(2), $"analysis took {elapsed.TotalSeconds:F1} s");
    }

    // The other text regexes, each fed the input shape that would make a backtracking pattern blow up, at the body cap.
    [Theory]
    [InlineData("word")]           // [\w.+-]+@... over a run of word characters with no '@'
    [InlineData("tags")]           // <[^>]{1,2000}> over a run of '<' with no '>'
    [InlineData("script")]         // <script>.*?</script> with no closing tag, many times
    [InlineData("arabic-space")]   // كلمة + whitespace run
    [InlineData("auth")]           // spf=... header pattern over a whitespace run
    public void Pathological_bodies_are_analysed_quickly(string shape)
    {
        var body = shape switch
        {
            "word" => new string('a', 60_000),
            "tags" => new string('<', 60_000),
            "script" => string.Concat(Enumerable.Repeat("<script>", 7_500)),
            "arabic-space" => "كلمة" + new string(' ', 59_990),
            _ => "x",
        };
        var headers = shape == "auth" ? "Authentication-Results: spf" + new string(' ', 59_990) : null;
        var elapsed = Time(new EmailSubmission
        {
            Subject = "Invoice", SenderEmail = "billing@example.com", Body = body, RawHeaders = headers,
            Attachments = [new EmailAttachment("a.zip")],
        });
        Assert.True(elapsed < TimeSpan.FromSeconds(2), $"{shape}: analysis took {elapsed.TotalSeconds:F1} s");
    }
}
