using System.Text.RegularExpressions;

namespace PhishingAnalyser.Core.Rules;

/// <summary>An attachment as the extension sees it in Gmail: only the name and type - the file itself is never sent.</summary>
public sealed record EmailAttachment(string Name, string? MimeType = null);

/// <summary>
/// Flags attachment types that current phishing and malware campaigns rely on. Judged purely from file names and
/// the email text - the file is never downloaded or opened, so there's no malware-handling risk on the server.
/// </summary>
public sealed partial class AttachmentAnalyser
{
    public const string Source = "attachments";

    private static readonly HashSet<string> Executable = new(StringComparer.OrdinalIgnoreCase)
        { "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "msi", "lnk", "jar", "cpl", "reg", "dll", "appx", "msix" };

    // Disk images are mounted as a drive, and files inside historically escaped Windows' "downloaded from the internet" warning.
    private static readonly HashSet<string> DiskImage = new(StringComparer.OrdinalIgnoreCase) { "iso", "img", "vhd", "vhdx" };

    // HTML/SVG attachments render a fake login page locally (HTML smuggling; the 2024-25 SVG phishing wave).
    private static readonly HashSet<string> Markup = new(StringComparer.OrdinalIgnoreCase) { "html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml" };

    private static readonly HashSet<string> MacroOrNote = new(StringComparer.OrdinalIgnoreCase) { "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "ppam", "one", "onepkg" };

    private static readonly HashSet<string> Archive = new(StringComparer.OrdinalIgnoreCase) { "zip", "rar", "7z", "gz", "tar", "ace", "arj", "cab" };

    private static readonly HashSet<string> DocumentLike = new(StringComparer.OrdinalIgnoreCase) { "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt" };

    // "password: 1234", "pwd 1234", "كلمة المرور: 1234" - the password for an attached archive, given so scanners can't look inside.
    // Atomic groups: plain \s*[:=]?\s* backtracked quadratically on a long whitespace run after "pwd" - 60k spaces took
    // 10 s per archive attachment (red-team review). Whitespace can never be part of the match after it, so nothing is lost.
    [GeneratedRegex(@"(?:password|passcode|pwd|pass|كلمة(?>\s*)(?:المرور|السر))(?>\s*)[:=]?(?>\s*)\S{3,}", RegexOptions.IgnoreCase)]
    private static partial Regex PasswordInText();

    public ComponentResult Analyse(IReadOnlyList<EmailAttachment>? attachments, string? body)
    {
        if (attachments is not { Count: > 0 })
            return new ComponentResult(Source, 0, true, []);

        var findings = new List<Finding>();
        var passwordGiven = new Lazy<bool>(() => PasswordInText().IsMatch(body ?? "")); // once per email, not per archive
        foreach (var attachment in attachments.Take(50))
            findings.AddRange(AnalyseOne(attachment, passwordGiven));

        var distinct = findings.GroupBy(f => f.Code).Select(g => g.MaxBy(f => f.Weight)!).OrderByDescending(f => f.Weight).ToList();
        return new ComponentResult(Source, Scoring.NoisyOr(distinct), true, distinct);
    }

    private static IEnumerable<Finding> AnalyseOne(EmailAttachment attachment, Lazy<bool> passwordGiven)
    {
        var name = attachment.Name.Trim();

        // U+202E flips the text direction so "invoice_fdp.exe" displays as "invoice_exe.pdf".
        if (name.Contains('‮'))
        {
            yield return new(Source, "rtlo-filename", "An attachment name uses a hidden character to disguise its real file type", 0.6,
                "اسم أحد المرفقات يستخدم حرفًا مخفيًا لإخفاء نوع الملف الحقيقي", name);
            name = name.Replace("‮", "");
        }

        var parts = name.Split('.');
        var ext = parts.Length > 1 ? parts[^1] : "";
        var inner = parts.Length > 2 ? parts[^2] : "";

        // "invoice.pdf.exe", "scan.jpg    .html"
        if (inner.Length > 0 && DocumentLike.Contains(inner.Trim()) && (Executable.Contains(ext) || Markup.Contains(ext) || DiskImage.Contains(ext)))
            yield return new(Source, "double-extension", $"'{name}' pretends to be a .{inner.Trim()} but is really a .{ext} file", 0.6,
                $"الملف '{name}' يتظاهر بأنه ‎.{inner.Trim()}‎ لكنه في الحقيقة ملف ‎.{ext}‎", name);

        if (Executable.Contains(ext))
            yield return new(Source, "executable-attachment", $"'{name}' is a program or script - opening it runs code on your computer", 0.6,
                $"الملف '{name}' برنامج أو سكربت - فتحه يشغّل تعليمات برمجية على جهازك", name);
        else if (DiskImage.Contains(ext))
            yield return new(Source, "disk-image-attachment", $"'{name}' is a disk image, a common way to smuggle malware past security warnings", 0.5,
                $"الملف '{name}' صورة قرص، وهي طريقة شائعة لتمرير البرمجيات الخبيثة متجاوزةً التحذيرات الأمنية", name);
        else if (Markup.Contains(ext))
            yield return new(Source, "html-attachment", $"'{name}' is a web page/SVG attachment - these often open a fake sign-in page", 0.45,
                $"الملف '{name}' صفحة ويب أو صورة SVG مرفقة - وغالبًا ما تفتح صفحة تسجيل دخول مزيفة", name);
        else if (MacroOrNote.Contains(ext))
            yield return new(Source, "macro-attachment", $"'{name}' can contain macros or embedded files that run code", 0.4,
                $"الملف '{name}' قد يحتوي على وحدات ماكرو أو ملفات مضمّنة تشغّل تعليمات برمجية", name);
        else if (Archive.Contains(ext) && passwordGiven.Value)
            yield return new(Source, "password-archive", $"'{name}' is an archive whose password is given in the email - a trick to stop security scanners looking inside", 0.4,
                $"الملف '{name}' أرشيف كلمة مروره مذكورة في الرسالة - وهي حيلة لمنع برامج الفحص الأمني من فحص محتواه", name);
    }
}
