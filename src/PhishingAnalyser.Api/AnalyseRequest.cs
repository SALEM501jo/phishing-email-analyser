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
        // "is null" checks: JSON like {"links":[null]} deserialises to a list holding null, which must be a 400, not a crash.
        if (Links?.Count > MaxLinks || Links?.Any(l => l is null) == true)
            errors["links"] = [$"At most {MaxLinks} links are accepted, and none may be null."];
        if (Attachments?.Count > 100 || Attachments?.Any(a => a is null) == true)
            errors["attachments"] = ["At most 100 attachments are accepted, and none may be null."];
        if (QrCodeUrls?.Count > 20 || QrCodeUrls?.Any(u => u is null || u.Length > 2048) == true)
            errors["qrCodeUrls"] = ["At most 20 QR URLs of up to 2048 characters are accepted."];
        return errors;
    }

    /// <summary>
    /// Long names are shortened in the MIDDLE: cutting the end would drop the extension, and "Remittance_000...000.html"
    /// (270 characters) would no longer be recognised as an HTML attachment (red-team review).
    /// </summary>
    internal static string ClampAttachmentName(string name) =>
        name.Length <= MaxAttachmentName ? name : string.Concat(name.AsSpan(0, MaxAttachmentName - 61), "\u2026", name.AsSpan(name.Length - 60));

    private const int MaxAttachmentName = 255;

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
            .Select(a => new PhishingAnalyser.Core.Rules.EmailAttachment(ClampAttachmentName(a.Name!.Trim()), a.MimeType))
            .ToList(),
        QrCodeUrls = QrCodeUrls?.Where(u => !string.IsNullOrWhiteSpace(u)).Select(u => u.Trim()).ToList(),
    };
}
