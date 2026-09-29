using PhishingAnalyser.Core.Content;

namespace PhishingAnalyser.Tests;

/// <summary>
/// The rules of Hugging Face's fast BERT tokenizer, on a tiny vocabulary (so this runs without a model).
/// Id-for-id agreement with the real vocabulary is proven by TransformerParityTests on every exported model.
/// </summary>
public class HfBertTokenizerTests : IDisposable
{
    //                                    0       1       2       3     4    5    6    7    8      9      10
    private static readonly string[] Vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "a", "b", "$", "|", "hel", "##lo", "##b"];
    private const int Cls = 2, Sep = 3, Unk = 1;
    private readonly string _path = Path.GetTempFileName();
    private readonly HfBertTokenizer _tokenizer;

    public HfBertTokenizerTests()
    {
        File.WriteAllLines(_path, Vocab);
        _tokenizer = HfBertTokenizer.Load(_path);
    }

    public void Dispose() => File.Delete(_path);

    [Theory]
    [InlineData("a$b", new[] { 4, 6, 5 })]            // ASCII symbols are punctuation: split out, never dropped
    [InlineData("a | b", new[] { 4, 7, 5 })]
    [InlineData("hello", new[] { 8, 9 })]             // greedy longest match with ## continuations
    [InlineData("ab", new[] { 4, 10 })]
    [InlineData("a​b", new[] { 4, 10 })]         // zero-width space (Cf) removed -> "ab"
    [InlineData("a\tb\r\nb", new[] { 4, 5, 5 })]      // tabs and newlines are whitespace
    [InlineData("a��b", new[] { 4, 10 })]   // replacement characters removed
    [InlineData("a\U0001F600b", new[] { Unk })]       // emoji: one unknown word, not dropped
    [InlineData("a⹫b", new[] { Unk })]           // unassigned code point kept -> unknown word
    [InlineData("hellx a", new[] { Unk, 4 })]         // an unmatchable word is ONE [UNK]
    public void Matches_hugging_face_rules(string text, int[] body) =>
        Assert.Equal([Cls, .. body, Sep], _tokenizer.Encode(text, 256));

    [Fact]
    public void Words_over_100_characters_are_unknown() =>
        Assert.Equal([Cls, Unk, Sep], _tokenizer.Encode(new string('a', 101), 256));

    [Fact]
    public void Truncates_to_max_length_keeping_sep() =>
        Assert.Equal([Cls, 4, 4, Sep], _tokenizer.Encode("a a a a a", 4));
}
