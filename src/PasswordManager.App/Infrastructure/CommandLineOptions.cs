using System.IO;
using PasswordManager.Storage;

namespace PasswordManager.App.Infrastructure;

internal sealed record CommandLineOptions(string? Language, IReadOnlyList<string> VaultPaths)
{
    public static CommandLineOptions Parse(IReadOnlyList<string> arguments)
    {
        string? language = null;
        var paths = new List<string>();

        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index];
            if (string.Equals(argument, "--lang", StringComparison.OrdinalIgnoreCase))
            {
                if (++index >= arguments.Count || arguments[index] is not ("ru" or "en"))
                {
                    throw new ArgumentException("--lang accepts only ru or en.");
                }

                language = arguments[index];
                continue;
            }

            if (argument.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException("Unknown command-line option.");
            }

            var path = Path.GetFullPath(argument);
            if (path.EndsWith(VaultRepository.VaultExtension, StringComparison.OrdinalIgnoreCase) && File.Exists(path))
            {
                paths.Add(path);
            }
        }

        return new CommandLineOptions(language, paths.Distinct(StringComparer.OrdinalIgnoreCase).Take(16).ToArray());
    }
}
