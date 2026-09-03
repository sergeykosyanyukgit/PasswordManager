using System.Text;

namespace PasswordManager.Ssh;

public sealed class Osc52Filter
{
    private readonly StringBuilder pending = new();

    public string Filter(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        pending.Append(input);
        var output = new StringBuilder(pending.Length);
        var index = 0;

        while (index < pending.Length)
        {
            var start = IndexOfOsc52(pending, index, out var prefixLength);
            if (start < 0)
            {
                var safeLength = pending.Length - index - PartialSequenceSuffixLength(pending, index);
                output.Append(pending, index, safeLength);
                index += safeLength;
                break;
            }

            output.Append(pending, index, start - index);
            var end = FindOscEnd(pending, start + prefixLength);
            if (end < 0)
            {
                index = start;
                break;
            }

            index = end;
        }

        pending.Remove(0, index);
        if (pending.Length > 1024 * 1024)
        {
            pending.Clear();
        }

        return output.ToString();
    }

    private static int PartialSequenceSuffixLength(StringBuilder text, int start)
    {
        return Math.Max(
            PartialSequenceSuffixLength(text, start, "\u001b]52;"),
            PartialSequenceSuffixLength(text, start, "\u009d52;"));
    }

    private static int PartialSequenceSuffixLength(StringBuilder text, int start, string sequence)
    {
        for (var length = Math.Min(sequence.Length - 1, text.Length - start); length > 0; length--)
        {
            var offset = text.Length - length;
            var matches = true;
            for (var index = 0; index < length; index++)
            {
                if (text[offset + index] != sequence[index])
                {
                    matches = false;
                    break;
                }
            }

            if (matches)
            {
                return length;
            }
        }

        return 0;
    }

    private static int IndexOfOsc52(StringBuilder text, int start, out int prefixLength)
    {
        for (var i = start; i < text.Length; i++)
        {
            if (i <= text.Length - 5 &&
                text[i] == '\u001b' && text[i + 1] == ']' && text[i + 2] == '5' && text[i + 3] == '2' && text[i + 4] == ';')
            {
                prefixLength = 5;
                return i;
            }

            if (i <= text.Length - 4 &&
                text[i] == '\u009d' && text[i + 1] == '5' && text[i + 2] == '2' && text[i + 3] == ';')
            {
                prefixLength = 4;
                return i;
            }
        }

        prefixLength = 0;
        return -1;
    }

    private static int FindOscEnd(StringBuilder text, int start)
    {
        for (var i = start; i < text.Length; i++)
        {
            if (text[i] == '\a')
            {
                return i + 1;
            }

            if (text[i] == '\u001b' && i + 1 < text.Length && text[i + 1] == '\\')
            {
                return i + 2;
            }

            if (text[i] == '\u009c')
            {
                return i + 1;
            }
        }

        return -1;
    }
}
