using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using PhishingAnalyser.Core;
using PhishingAnalyser.Core.Content;
using PhishingAnalyser.Core.Rules;

namespace PhishingAnalyser.Tests;

public class ArabicTextTests
{
    [Theory]
    [InlineData("أرامكس", "ارامكس")]           // hamza on alef
    [InlineData("إلغاء", "الغاء")]             // hamza under alef
    [InlineData("حِسَابُكَ", "حسابك")]           // diacritics
    [InlineData("البـــنك", "البنك")]          // tatweel stretching
    [InlineData("مكتبة", "مكتبه")]             // taa marbuta
    public void Normalises_orthographic_variants(string input, string expected) =>
        Assert.Equal(expected, ArabicText.Normalize(input));

    [Fact]
    public void Latin_text_is_untouched() => Assert.Equal("PayPal", ArabicText.Normalize("PayPal"));
}

public class LanguageDetectionTests
{
    [Theory]
    [InlineData("عزيزي العميل، تم تعليق حسابك مؤقتا. يرجى الضغط على الرابط أدناه لتحديث بياناتك", "ar")]
    [InlineData("عميلنا العزيز، شحنتك من Aramex بانتظار دفع رسوم الجمارك عبر الرابط https://x.test", "ar")] // mixed script
    [InlineData("Please verify your account within 24 hours or it will be suspended. Click the link below to continue.", "en")]
    [InlineData("Prezado cliente, sua conta foi suspensa. Clique no link abaixo para atualizar seus dados cadastrais imediatamente.", "other")]
    public void Detects_language(string text, string expected) =>
        Assert.Equal(expected, LanguageHeuristics.Detect(text));
}

public class ArabicBrandTests
{
    private readonly BrandCatalog _brands = BrandCatalog.Default;

    [Theory]
    [InlineData("البنك العربي", "Arab Bank")]
    [InlineData("خدمة عملاء أرامكس", "Aramex")]            // hamza variant must still match
    [InlineData("اي فواتيركم - تنبيه دفع", "eFAWATEERcom")]
    [InlineData("مصرف الراجحي", "Al Rajhi Bank")]
    [InlineData("فريق دعم باي بال", "PayPal")]
    [InlineData("Arab Bank Alerts", "Arab Bank")]
    public void Finds_arabic_and_regional_brands_in_display_names(string displayName, string brand) =>
        Assert.Equal(brand, _brands.MentionedIn(displayName)?.Name);

    [Theory]
    [InlineData("زين محمد")]     // Zain is a common first name - not the telecom
    [InlineData("كريم أحمد")]    // Kareem - not Careem
    public void Common_first_names_are_not_brands(string displayName) =>
        Assert.Null(_brands.MentionedIn(displayName));

    [Theory]
    [InlineData("cab-booking.com")]    // "cab" is Cairo Amman Bank's label but also a word
    [InlineData("stc-events.org")]
    public void Short_ambiguous_labels_are_not_impersonation(string host) =>
        Assert.Null(_brands.DetectImpersonation(host));

    [Theory]
    [InlineData("efawateercom-pay.net", "brand-in-domain")]
    [InlineData("arabbank.jo.secure-login.xyz", "brand-in-subdomain")]
    [InlineData("alrajhlbank.com", "typosquat")]   // "l" for "i": one edit away
    public void Detects_regional_impersonation(string host, string kind) =>
        Assert.Equal(kind, _brands.DetectImpersonation(host)?.Kind);

    [Fact]
    public void Arabic_messages_are_provided_for_findings()
    {
        var result = new HeaderAnalyser(_brands).Analyse(new EmailSubmission { SenderName = "البنك العربي", SenderEmail = "alerts.arabbank@gmail.com" });
        var finding = Assert.Single(result.Findings);
        Assert.Equal("brand-display-freemail", finding.Code);
        Assert.Contains("Arab Bank", finding.In(Languages.Arabic));
        Assert.True(ArabicText.ContainsArabic(finding.In(Languages.Arabic)));
        Assert.False(ArabicText.ContainsArabic(finding.In(Languages.English)));
    }
}

public class ArabicApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private static readonly string ModelPath = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "models", "phishing-content-model.zip"));

    [Fact]
    public async Task Arabic_phish_gets_arabic_reasons_and_is_still_flagged_by_rules()
    {
        var client = factory.WithWebHostBuilder(b => b.UseSetting("ContentModel:Path", ModelPath)).CreateClient();
        var response = await client.PostAsJsonAsync("/api/v1/analyse", new
        {
            subject = "تنبيه: تم تعليق حسابك في البنك العربي",
            senderName = "البنك العربي",
            senderEmail = "security@arabbank-jo-verify.com",
            body = "عزيزي العميل، تم رصد نشاط غير معتاد على حسابك. يرجى تحديث بياناتك خلال ٢٤ ساعة عبر الرابط أدناه لتجنب إيقاف الحساب نهائيًا.",
            links = new[] { new { text = "www.arabbank.jo", href = "http://arabbank-jo-verify.com/login" } },
        });

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("ar", json.GetProperty("language").GetString());
        Assert.Equal("phishing", json.GetProperty("verdict").GetString());
        Assert.All(json.GetProperty("reasons").EnumerateArray(), r => Assert.True(ArabicText.ContainsArabic(r.GetString())));
    }
}
