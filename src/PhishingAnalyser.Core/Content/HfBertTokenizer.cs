using System.Globalization;
using System.Text;

namespace PhishingAnalyser.Core.Content;

/// <summary>
/// BERT WordPiece tokenisation that reproduces Hugging Face's fast tokenizer (the one the model was trained with)
/// id for id. Microsoft.ML.Tokenizers' BertTokenizer differs on exactly the characters phishing mail is full of:
/// it drops ASCII symbols ($ + = | ~ ^ &lt; &gt; `), emoji and currency signs, and treats tabs, zero-width characters,
/// underscores and combining accents differently. Rules, following tokenizers' BertNormalizer, BertPreTokenizer
/// and WordPiece (cased model, no accent stripping):
///   1. drop NUL, U+FFFD and control/format/private-use characters (Cc Cf Cs Co; unassigned ones stay) except \t \n \r; map whitespace to ' '
///   2. put spaces around CJK ideographs
///   3. split on whitespace; every punctuation character (ASCII punctuation or Unicode P*) is its own word
///   4. greedy longest-match WordPiece per word ("##" continuations); a word that can't be matched, or longer
///      than 100 characters, becomes a single [UNK]
/// Characters are Unicode scalar values (Runes), as in Rust - emoji are one character, not two UTF-16 units.
/// </summary>
public sealed class HfBertTokenizer
{
    private const int MaxCharsPerWord = 100;
    private readonly Dictionary<string, int> _vocab;
    private readonly bool _lowercase;
    private readonly int _cls, _sep, _unk;

    private HfBertTokenizer(Dictionary<string, int> vocab, bool lowercase)
    {
        _vocab = vocab;
        _lowercase = lowercase;
        _cls = vocab["[CLS]"];
        _sep = vocab["[SEP]"];
        _unk = vocab["[UNK]"];
    }

    public static HfBertTokenizer Load(string vocabPath, bool lowercase = false)
    {
        var vocab = new Dictionary<string, int>(StringComparer.Ordinal);
        var id = 0;
        foreach (var line in File.ReadLines(vocabPath, Encoding.UTF8))
            vocab.TryAdd(line.TrimEnd('\r', '\n'), id++);
        return new HfBertTokenizer(vocab, lowercase);
    }

    /// <summary>[CLS] word pieces [SEP], truncated to <paramref name="maxLength"/> like Hugging Face.</summary>
    public int[] Encode(string text, int maxLength)
    {
        var ids = new List<int> { _cls };
        foreach (var word in PreTokenize(Normalize(text)))
        {
            WordPiece(word, ids);
            if (ids.Count >= maxLength - 1)
                break;
        }
        if (ids.Count > maxLength - 1)
            ids.RemoveRange(maxLength - 1, ids.Count - (maxLength - 1));
        ids.Add(_sep);
        return [.. ids];
    }

    private string Normalize(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            var cp = rune.Value;
            if (cp == 0 || cp == 0xFFFD || IsControl(rune))
                continue;
            if (IsWhitespace(rune))
                sb.Append(' ');
            else if (IsChinese(cp))
                sb.Append(' ').Append(rune.ToString()).Append(' ');
            else
                sb.Append(rune.ToString());
        }
        return _lowercase ? sb.ToString().ToLowerInvariant() : sb.ToString();
    }

    private static IEnumerable<string> PreTokenize(string text)
    {
        var word = new StringBuilder();
        foreach (var rune in text.EnumerateRunes())
        {
            if (Rune.IsWhiteSpace(rune))
            {
                if (word.Length > 0) { yield return word.ToString(); word.Clear(); }
            }
            else if (IsPunctuation(rune))
            {
                if (word.Length > 0) { yield return word.ToString(); word.Clear(); }
                yield return rune.ToString();
            }
            else
            {
                word.Append(rune.ToString());
            }
        }
        if (word.Length > 0)
            yield return word.ToString();
    }

    private void WordPiece(string word, List<int> ids)
    {
        // Work in runes so that substrings never split a surrogate pair.
        var runes = word.EnumerateRunes().Select(r => r.ToString()).ToArray();
        if (runes.Length > MaxCharsPerWord)
        {
            ids.Add(_unk);
            return;
        }

        var pieces = new List<int>();
        var start = 0;
        while (start < runes.Length)
        {
            var end = runes.Length;
            var found = -1;
            while (start < end)
            {
                var piece = string.Concat(runes[start..end]);
                if (start > 0)
                    piece = "##" + piece;
                if (_vocab.TryGetValue(piece, out var id)) { found = id; break; }
                end--;
            }
            if (found < 0)
            {
                ids.Add(_unk); // the whole word, as Hugging Face does
                return;
            }
            pieces.Add(found);
            start = end;
        }
        ids.AddRange(pieces);
    }

    // Rust tokenizers' is_control: not \t \n \r, and Cc Cf Cs Co. Unassigned code points (Cn) are KEPT -
    // verified against the Python tokenizer (U+2E6B and U+07B4 survive its normalisation).
    private static bool IsControl(Rune rune) => rune.Value is not ('\t' or '\n' or '\r') &&
        Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
            or UnicodeCategory.PrivateUse;

    private static bool IsWhitespace(Rune rune) => rune.Value is ' ' or '\t' or '\n' or '\r' || Rune.IsWhiteSpace(rune);

    // ASCII punctuation (which includes symbols such as $ + < = > ^ ` | ~) or any Unicode punctuation category.
    private static bool IsPunctuation(Rune rune) =>
        rune.Value is >= 33 and <= 47 or >= 58 and <= 64 or >= 91 and <= 96 or >= 123 and <= 126 ||
        Rune.GetUnicodeCategory(rune) is UnicodeCategory.ConnectorPunctuation or UnicodeCategory.DashPunctuation
            or UnicodeCategory.OpenPunctuation or UnicodeCategory.ClosePunctuation or UnicodeCategory.InitialQuotePunctuation
            or UnicodeCategory.FinalQuotePunctuation or UnicodeCategory.OtherPunctuation;

    private static bool IsChinese(int cp) =>
        cp is >= 0x4E00 and <= 0x9FFF or >= 0x3400 and <= 0x4DBF or >= 0x20000 and <= 0x2A6DF or >= 0x2A700 and <= 0x2B73F
            or >= 0x2B740 and <= 0x2B81F or >= 0x2B820 and <= 0x2CEAF or >= 0xF900 and <= 0xFAFF or >= 0x2F800 and <= 0x2FA1F;
}
