using System.Security.Cryptography;
using PasswordManager.Core.Validation;

namespace PasswordManager.Security;

public static class PasswordGenerator
{
    private const string Lowercase = "abcdefghijkmnopqrstuvwxyz";
    private const string Uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Digits = "23456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{}:,.?";

    public static string GeneratePassword(PasswordGenerationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Length is < PasswordPolicy.MinimumGeneratedPasswordLength or > PasswordPolicy.MaximumGeneratedPasswordLength)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Password length must be between 15 and 128.");
        }

        var groups = new List<string>();
        AddGroup(groups, options.IncludeLowercase, Lowercase);
        AddGroup(groups, options.IncludeUppercase, Uppercase);
        AddGroup(groups, options.IncludeDigits, Digits);
        AddGroup(groups, options.IncludeSymbols, Symbols);
        if (groups.Count == 0 || options.Length < groups.Count)
        {
            throw new ArgumentException("At least one character class is required.", nameof(options));
        }

        var result = new char[options.Length];
        var index = 0;
        foreach (var group in groups)
        {
            result[index++] = group[RandomNumberGenerator.GetInt32(group.Length)];
        }

        var alphabet = string.Concat(groups);
        while (index < result.Length)
        {
            result[index++] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }

        for (var i = result.Length - 1; i > 0; i--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(i + 1);
            (result[i], result[swapIndex]) = (result[swapIndex], result[i]);
        }

        return new string(result);
    }

    public static string GeneratePassphrase(int wordCount = 6, string separator = "-")
    {
        if (wordCount is < 6 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(wordCount));
        }

        ArgumentNullException.ThrowIfNull(separator);
        var words = new string[wordCount];
        for (var i = 0; i < words.Length; i++)
        {
            words[i] = PassphraseWords.GetWord(RandomNumberGenerator.GetInt32(PassphraseWords.Count));
        }

        return string.Join(separator, words);
    }

    private static void AddGroup(List<string> groups, bool include, string group)
    {
        if (include)
        {
            groups.Add(group);
        }
    }
}

public sealed record PasswordGenerationOptions(
    int Length = 24,
    bool IncludeLowercase = true,
    bool IncludeUppercase = true,
    bool IncludeDigits = true,
    bool IncludeSymbols = true);

internal static class PassphraseWords
{
    private static readonly string[] Onsets =
    [
        "b", "br", "c", "ch", "d", "f", "g", "gr", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t",
    ];

    private static readonly string[] Nuclei =
    [
        "a", "ae", "ai", "e", "ea", "ei", "i", "ia", "ie", "o", "oa", "oi", "u", "ua", "ue", "y", "yo", "ou",
    ];

    private static readonly string[] Codas =
    [
        "bar", "bel", "cen", "dor", "fin", "gan", "hel", "jor", "kel", "lin", "mor", "nal",
        "pel", "quin", "ran", "sel", "tor", "ven", "win", "xel", "yor", "zen", "ric", "lum",
    ];

    // 18 × 18 × 24 = 7,776 stable pronounceable tokens; six choices provide about 77.5 bits.
    internal const int Count = 7_776;

    internal static string GetWord(int index)
    {
        if (index is < 0 or >= Count)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        var coda = index % Codas.Length;
        index /= Codas.Length;
        var nucleus = index % Nuclei.Length;
        var onset = index / Nuclei.Length;
        return Onsets[onset] + Nuclei[nucleus] + Codas[coda];
    }
}
