using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class AttachmentTests
{
    private readonly AttachmentAnalyser _analyser = new();

    private IEnumerable<string> Codes(string name, string body = "") =>
        _analyser.Analyse([new EmailAttachment(name)], body).Findings.Select(f => f.Code);

    [Theory]
    [InlineData("setup.exe", "executable-attachment")]
    [InlineData("Invoice_2026.js", "executable-attachment")]
    [InlineData("shortcut.lnk", "executable-attachment")]
    [InlineData("Payment.iso", "disk-image-attachment")]
    [InlineData("Remittance.html", "html-attachment")]
    [InlineData("voicemail.svg", "html-attachment")]
    [InlineData("Q3-report.xlsm", "macro-attachment")]
    [InlineData("notes.one", "macro-attachment")]
    public void Flags_dangerous_types(string name, string code) => Assert.Contains(code, Codes(name));

    [Fact]
    public void Double_extension_is_flagged() => Assert.Contains("double-extension", Codes("invoice.pdf.exe"));

    [Fact]
    public void Right_to_left_override_is_flagged()
    {
        // Displays as "invoice_exe.pdf" but is "invoice_fdp.exe".
        var codes = Codes("invoice_‮fdp.exe").ToList();
        Assert.Contains("rtlo-filename", codes);
        Assert.Contains("executable-attachment", codes);
    }

    [Fact]
    public void Archive_is_only_flagged_when_its_password_is_in_the_email()
    {
        Assert.Empty(Codes("photos.zip", "Here are the holiday photos."));
        Assert.Contains("password-archive", Codes("invoice.zip", "Please open the attached invoice. Password: 4471"));
        Assert.Contains("password-archive", Codes("فاتورة.zip", "يرجى فتح الفاتورة المرفقة. كلمة المرور: 4471"));
    }

    [Theory]
    [InlineData("contract.pdf")]
    [InlineData("photo.jpg")]
    [InlineData("report.docx")]
    [InlineData("budget.xlsx")]
    public void Ordinary_documents_are_clean(string name) => Assert.Empty(Codes(name));

    [Fact]
    public void Qr_code_destination_goes_through_the_link_checks()
    {
        var analyser = new EmailAnalyser(new UnavailableContentClassifier(), new HeaderAnalyser(BrandCatalog.Default),
            new LinkAnalyser(BrandCatalog.Default), new ScoringOptions());
        var result = analyser.Analyse(new EmailSubmission
        {
            Subject = "MFA re-enrolment required", SenderEmail = "it@company.com", Body = "Scan the QR code with your phone.",
            QrCodeUrls = ["https://rnicrosoft-mfa.com/enrol"],
        });

        var codes = result.Breakdown.Links.Findings.Select(f => f.Code).ToList();
        Assert.Contains("qr-code-link", codes);
        Assert.Contains("lookalike-domain", codes);  // rnicrosoft -> microsoft, found only inside the QR code
    }
}
