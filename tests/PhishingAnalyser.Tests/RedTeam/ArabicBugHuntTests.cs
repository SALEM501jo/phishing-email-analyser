using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

/// <summary>Arabic end-to-end bug hunt: every test here FAILS on the current code and documents one confirmed bug.</summary>
public class ArabicBugHuntTests
{
    private static readonly BrandCatalog Brands = BrandCatalog.Default;

    private static EmailAnalyser Analyser(IContentClassifier? classifier = null) =>
        new(classifier ?? new UnavailableContentClassifier(), new HeaderAnalyser(Brands), new LinkAnalyser(Brands), new ScoringOptions());

    private static string Detect(string? subject, string? body) =>
        LanguageHeuristics.Detect(EmailTextNormalizer.Normalize(subject, body)); // exactly what both classifiers and EmailAnalyser do

    private sealed class FixedClassifier(ContentResult result) : IContentClassifier
    {
        public bool IsLoaded => true;
        public ModelInfo? Model => null;
        public ContentResult Classify(string? subject, string? body) => result;
    }

    // BUG 1 - an English email with a short Arabic signature is "other": the classifier's weight is halved.
    [Fact]
    public void Bug1_English_mail_with_an_Arabic_signature_is_still_English()
    {
        const string body =
            "Dear customer, your account has been suspended. Please verify your identity within 24 hours by clicking " +
            "the link below to avoid permanent closure.\n\nمع أطيب التحيات\nفريق خدمة العملاء\nعمّان - الأردن";
        Assert.Equal(Languages.English, Detect("Account suspended", body));
    }

    // BUG 2 - digits/URLs become the Latin placeholders "numtoken"/"urltoken" BEFORE detection and are counted as non-Arabic words.
    [Theory]
    [InlineData("إشعار حوالة واردة",
        "تم إيداع حوالة بمبلغ 1,250.000 JOD في حسابك رقم 0131-0003-02 بتاريخ 12/05/2025 الساعة 14:30:05. IBAN: JO94 CBJO 0010 0000 0000 0131 0003 02. المرجع: TRX-2025-0512-889431. الرصيد المتاح: 3,480.750 JOD")]
    // Not one Latin character in this one: Arabic letters and Arabic-Indic digits only.
    [InlineData("كشف حساب مختصر",
        "١٢/٠٥/٢٠٢٥ سحب ٢٥٫٥٠٠ ، ١٣/٠٥/٢٠٢٥ إيداع ١٥٠٫٠٠٠ ، ١٤/٠٥/٢٠٢٥ سحب ٤٠٫٢٥٠ ، الرصيد ١٬٢٤٥٫٧٥٠ دينار")]
    public void Bug2_Arabic_mail_full_of_numbers_is_still_Arabic(string subject, string body)
    {
        Assert.Equal(Languages.Arabic, Detect(subject, body));
        Assert.Equal(Languages.Arabic, Analyser().Analyse(new EmailSubmission { Subject = subject, Body = body }).Language);
    }

    // BUG 3 - fewer than three Arabic words default to English, although every word is Arabic.
    // The extension's privacy mode sends the subject only, so any Arabic email with a two-word subject gets an English banner.
    [Theory]
    [InlineData("تحديث الحساب", "")]
    [InlineData("تنبيه أمني", "https://arabbank-verify.xyz/login")]
    [InlineData(null, "رمز التحقق 482915")]
    public void Bug3_Short_all_Arabic_text_is_Arabic(string? subject, string? body)
    {
        var result = Analyser().Analyse(new EmailSubmission
        {
            Subject = subject, Body = body, SenderName = "البنك العربي", SenderEmail = "alerts.arabbank@gmail.com",
        });
        Assert.Equal(Languages.Arabic, result.Language);
        Assert.All(result.Reasons, r => Assert.True(ArabicText.ContainsArabic(r), r));
    }

    // BUG 4 - Persian and Urdu are reported as Arabic (any letter in U+0600-06FF counts as Arabic).
    [Theory]
    [InlineData("مشتری گرامی، حساب شما به دلیل فعالیت مشکوک مسدود شده است. لطفاً برای تأیید هویت خود روی پیوند زیر کلیک کنید")] // Persian
    [InlineData("محترم صارف، آپ کا اکاؤنٹ معطل کر دیا گیا ہے۔ براہ کرم اپنی معلومات کی تصدیق کے لیے نیچے دیے گئے لنک پر کلک کریں")] // Urdu
    public void Bug4_Persian_and_Urdu_are_not_Arabic(string body) =>
        Assert.Equal(Languages.Other, Detect(null, body));

    // BUG 5 - BrandCatalog.Squash has no NFKC and turns invisible format characters into spaces.
    [Theory]
    [InlineData("ﺍﻟﺒﻨﻚ ﺍﻟﻌﺮﺑﻲ", "Arab Bank")] // "البنك العربي" in presentation forms - renders identically
    [InlineData("أرا‍مكس", "Aramex")]      // zero-width joiner
    [InlineData("ارا‏مكس", "Aramex")]      // right-to-left mark
    [InlineData("ارا؜مكس", "Aramex")]      // Arabic letter mark
    [InlineData("Pay​Pal", "PayPal")]      // same hole for Latin names (zero-width space)
    public void Bug5_Display_name_brand_survives_presentation_forms_and_invisible_characters(string displayName, string brand)
    {
        Assert.Equal(brand, Brands.MentionedIn(displayName)?.Name);
        var findings = new HeaderAnalyser(Brands).Analyse(new EmailSubmission { SenderName = displayName, SenderEmail = "alerts@secure-notify.net" }).Findings;
        Assert.Contains(findings, f => f.Code == "brand-display-mismatch");
    }

    // BUG 6 - ArabicText.Normalize does not fold the Persian/Urdu look-alike letters nor the Arabic marks outside U+064B-065F.
    [Theory]
    [InlineData("البنک العربی", "Arab Bank")]       // keheh + Farsi yeh
    [InlineData("البنك العربی", "Arab Bank")]            // Farsi yeh only (identical to the final "ى" Normalize already folds)
    [InlineData("بنك القاهرہ عمان", "Cairo Amman Bank")] // heh goal
    [InlineData("الراۡجحي", "Al Rajhi Bank")]            // Quranic small high mark
    [InlineData("اراؐمكس", "Aramex")]                    // honorific mark U+0610
    public void Bug6_Display_name_brand_survives_lookalike_letters_and_extended_marks(string displayName, string brand) =>
        Assert.Equal(brand, Brands.MentionedIn(displayName)?.Name);

    // BUG 7 - EmailTextNormalizer's "invisible" set misses the Arabic letter mark, the bidi controls and the grapheme joiner:
    // a keyword split with them reaches the classifier as different tokens.
    [Theory]
    [InlineData("حسا؜بك")]         // Arabic letter mark
    [InlineData("حسا⁦⁩بك")]   // bidi isolates
    [InlineData("حسا‪‬بك")]   // bidi embedding + pop
    [InlineData("حسا͏بك")]         // combining grapheme joiner
    [InlineData("حساۖبك")]         // Quranic annotation mark
    public void Bug7_Normaliser_removes_invisible_characters_inside_Arabic_words(string obfuscated) =>
        Assert.Equal(EmailTextNormalizer.Normalize(null, "حسابك"), EmailTextNormalizer.Normalize(null, obfuscated));

    // BUG 8 - the keyword "البنك العربي" is a prefix of other real banks' names: genuine Arab National Bank mail is "suspicious".
    [Fact]
    public void Bug8_Arab_National_Bank_is_not_an_Arab_Bank_impersonation()
    {
        var result = Analyser().Analyse(new EmailSubmission
        {
            Subject = "كشف حسابك الشهري",
            Body = "عميلنا العزيز، مرفق كشف حسابك لشهر أيار. مع تحيات البنك العربي الوطني",
            SenderName = "البنك العربي الوطني",
            SenderEmail = "alerts@anb.com.sa",
        });
        Assert.DoesNotContain(result.Breakdown.Headers.Findings, f => f.Code == "brand-display-mismatch");
        Assert.Equal(Verdicts.Safe, result.Verdict);
    }

    // BUG 9 - a preview-language (Arabic) email that the model alone makes "suspicious" has no reason at all.
    [Fact]
    public void Bug9_Suspicious_Arabic_verdict_explains_itself()
    {
        var preview = new ContentResult(true, 0.97, 0, [], LanguageSupported: false, Language: Languages.Arabic, LanguagePreview: true);
        var result = Analyser(new FixedClassifier(preview)).Analyse(new EmailSubmission
        {
            Subject = "تم تعليق حسابك",
            Body = "عزيزي العميل، تم تعليق حسابك مؤقتا. يرجى تحديث بياناتك خلال 24 ساعة لتجنب الإيقاف النهائي.",
        });
        Assert.Equal(Verdicts.Suspicious, result.Verdict);
        Assert.NotEmpty(result.Reasons);
    }
}
