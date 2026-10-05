using System.Text.RegularExpressions;
using PhishingAnalyser.Core;

namespace PhishingAnalyser.Api;

/// <summary>
/// The public "try it" endpoint: anyone can paste a sample email, without a key. Deliberately smaller than the real
/// API - short fields, no headers or attachments, and NO outside lookups (domain age, blocklists, short-link
/// expansion), so an anonymous visitor can never make this server contact other sites. Nothing is stored.
/// </summary>
public sealed partial class DemoRequest
{
    private const int MaxSubject = 300, MaxBody = 5_000, MaxSender = 200, MaxUrl = 500, MaxLinks = 10;

    public string? Subject { get; init; }
    public string? SenderName { get; init; }
    public string? SenderEmail { get; init; }
    public string? Body { get; init; }
    public string? LinkText { get; init; }
    public string? LinkUrl { get; init; }

    [GeneratedRegex(@"https?://[^\s<>)\]]{4,500}", RegexOptions.IgnoreCase)]
    private static partial Regex UrlInText();

    public Dictionary<string, string[]> Validate()
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(Subject) && string.IsNullOrWhiteSpace(Body))
            errors["body"] = ["Provide a subject or a body."];
        if (Subject?.Length > MaxSubject || Body?.Length > MaxBody)
            errors["body"] = [$"The demo accepts a subject of up to {MaxSubject} and a body of up to {MaxBody} characters."];
        if (SenderName?.Length > MaxSender || SenderEmail?.Length > MaxSender)
            errors["sender"] = [$"Sender name and address: at most {MaxSender} characters each."];
        if (LinkText?.Length > MaxUrl || LinkUrl?.Length > MaxUrl)
            errors["link"] = [$"Link text and address: at most {MaxUrl} characters each."];
        return errors;
    }

    /// <summary>The optional explicit link, plus the http(s) addresses written in the body (as a mail client would link them).</summary>
    public EmailSubmission ToSubmission()
    {
        var links = new List<EmailLink>();
        if (!string.IsNullOrWhiteSpace(LinkUrl))
            links.Add(new EmailLink(string.IsNullOrWhiteSpace(LinkText) ? LinkUrl.Trim() : LinkText.Trim(), LinkUrl.Trim()));
        foreach (Match m in UrlInText().Matches(Body ?? ""))
            if (links.Count < MaxLinks && links.All(l => l.Href != m.Value))
                links.Add(new EmailLink(m.Value, m.Value));
        return new EmailSubmission
        {
            Subject = Subject?.Trim(), SenderName = SenderName?.Trim(), SenderEmail = SenderEmail?.Trim(), Body = Body, Links = links,
        };
    }
}

/// <summary>One allowance shared by ALL demo visitors per minute, on top of the per-visitor limit: the demo must never crowd the server.</summary>
public sealed class DemoBudget(int perMinute)
{
    private readonly object _gate = new();
    private long _window;
    private int _used;

    public bool TryTake()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
        lock (_gate)
        {
            if (now != _window)
                (_window, _used) = (now, 0);
            return ++_used <= perMinute;
        }
    }
}
