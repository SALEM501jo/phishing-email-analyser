using PhishingAnalyser.Core;

namespace PhishingAnalyser.Api;

public sealed record LinkDto(string? Text, string? Href);

/// <summary>Request body for POST /api/v1/analyse. Everything is optional; send what the page exposes.</summary>
public sealed class AnalyseRequest
{
    private const int MaxBody = 100_000;
    private const int MaxHeaders = 64_000;
    private const int MaxLinks = 500;

    public string? Subject { get; init; }
    public string? SenderName { get; init; }
    public string? SenderEmail { get; init; }
    public string? ReplyTo { get; init; }
    public string? Body { get; init; }
    public List<LinkDto>? Links { get; init; }
    public string? RawHeaders { get; init; }

    public Dictionary<string, string[]> Validate()
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(Body) && string.IsNullOrWhiteSpace(Subject) && string.IsNullOrWhiteSpace(SenderEmail))
            errors["body"] = ["Provide at least a subject, body or sender."];
        if (Body?.Length > MaxBody)
            errors["body"] = [$"Body must be at most {MaxBody} characters."];
        if (RawHeaders?.Length > MaxHeaders)
            errors["rawHeaders"] = [$"Raw headers must be at most {MaxHeaders} characters."];
        if (Links?.Count > MaxLinks)
            errors["links"] = [$"At most {MaxLinks} links are accepted."];
        return errors;
    }

    public EmailSubmission ToSubmission() => new()
    {
        Subject = Subject?.Trim(),
        SenderName = SenderName?.Trim(),
        SenderEmail = SenderEmail?.Trim(),
        ReplyTo = ReplyTo?.Trim(),
        Body = Body,
        RawHeaders = RawHeaders,
        Links = Links?
            .Where(l => !string.IsNullOrWhiteSpace(l.Href))
            .Select(l => new EmailLink(l.Text?.Trim(), l.Href!.Trim()))
            .ToList(),
    };
}
