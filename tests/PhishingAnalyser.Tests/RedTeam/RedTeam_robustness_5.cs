using System.Text;
using System.Text.RegularExpressions;
using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Tests;

/// <summary>
/// Found by the red-team timing test on CI: the &lt;script&gt;/&lt;style&gt; regex rescanned the rest of the text for every
/// unclosed tag. Its linear replacement must produce exactly what training saw - checked against the original regex.
/// </summary>
public class RedTeam_robustness_5
{
    private static readonly Regex Original = new(@"<(script|style)\b[^>]*>.*?</\1\s*>", RegexOptions.Singleline | RegexOptions.IgnoreCase);

    private static readonly string[] Tokens =
    [
        "<script>", "<SCRIPT type=\"x\">", "<script", "</script>", "</Script  >", "</scriptx>", "</script", "<scripts>",
        "<style>", "<style media=a>", "</style>", "</STYLE\n>", "<styles>", "ſcript", "<ſcript>", "<", ">", "</", "/",
        "a", "b c", " ", "\n", "<div>", "</div>", "<p class=s>", "<!-- <script> -->", "script", "style",
    ];

    [Fact]
    public void Same_output_as_the_regex_training_used()
    {
        var random = new Random(20261001);
        for (var n = 0; n < 20_000; n++)
        {
            var sb = new StringBuilder();
            for (var t = random.Next(0, 24); t > 0; t--)
                sb.Append(Tokens[random.Next(Tokens.Length)]);
            var text = sb.ToString();
            Assert.Equal(Original.Replace(text, " "), EmailTextNormalizer.RemoveScriptAndStyle(text));
        }
    }

    [Theory]
    [InlineData("Hi <style>p{color:red}</style>there<script>alert(1)</script>!", "Hi  there !")]
    [InlineData("<script>a</script><script>b", " <script>b")]
    [InlineData("no markup", "no markup")]
    public void Removes_closed_blocks_only(string text, string expected) =>
        Assert.Equal(expected, EmailTextNormalizer.RemoveScriptAndStyle(text));
}
