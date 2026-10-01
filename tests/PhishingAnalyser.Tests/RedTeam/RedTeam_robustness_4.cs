using System.Xml.Linq;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Tests;

/// <summary>
/// Red-team finding: the API ran in invariant-globalization mode, where .NET silently skips NFKC - so in production the
/// models saw "𝐏𝐚𝐲𝐏𝐚𝐥" and Arabic presentation forms unfolded, while training (and every offline number) had folded them.
/// </summary>
public class RedTeam_robustness_4
{
    [Theory]
    [InlineData("𝐕𝐞𝐫𝐢𝐟𝐲 𝐏𝐚𝐲𝐏𝐚𝐥", "Verify PayPal")]  // mathematical bold
    [InlineData("Ｖｅｒｉｆｙ", "Verify")]             // full-width
    [InlineData("ﻣﻢ", "مم")]                          // Arabic presentation forms
    public void Compatibility_characters_are_folded_like_in_training(string text, string expected)
    {
        Assert.True(EmailTextNormalizer.NormalizationAvailable);
        Assert.Equal(expected, EmailTextNormalizer.Normalize(null, text));
    }

    [Fact]
    public void The_api_does_not_run_in_invariant_globalization_mode()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Directory.Build.props")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var project = XDocument.Load(Path.Combine(dir.FullName, "src", "PhishingAnalyser.Api", "PhishingAnalyser.Api.csproj"));
        var invariant = project.Descendants("InvariantGlobalization").Select(e => e.Value.Trim()).LastOrDefault();
        Assert.NotEqual("true", invariant, StringComparer.OrdinalIgnoreCase);
    }
}
