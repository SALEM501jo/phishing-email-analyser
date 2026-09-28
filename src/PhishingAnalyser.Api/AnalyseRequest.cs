using PhishingAnalyser.Core;

namespace PhishingAnalyser.Api;

public sealed record LinkDto(string? Text, string? Href);

public sealed record AttachmentDto(string? Name, string? MimeType);

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
    public List<AttachmentDto>? Attachments { get; init; }
    public List<string>? QrCodeUrls { get; init; }

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
        if (Attachments?.Count > 100)
            errors["attachments"] = ["At most 100 attachments are accepted."];
        if (QrCodeUrls?.Count > 20 || QrCodeUrls?.Any(u => u.Length > 2048) == true)
            errors["qrCodeUrls"] = ["At most 20 QR URLs of up to 2048 characters are accepted."];
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
        Attachments = Attachments?
            .Where(a => !string.IsNullOrWhiteSpace(a.Name))
            .Select(a => new PhishingAnalyser.Core.Rules.EmailAttachment(a.Name!.Trim()[..Math.Min(a.Name!.Trim().Length, 255)], a.MimeType))
            .ToList(),
        QrCodeUrls = QrCodeUrls?.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()).ToList(),
    };
}
