using FsCheck.Xunit;
using PasswordManager.Security;

namespace PasswordManager.Tests;

public sealed class ParserPropertyTests
{
    [Property(MaxTest = 100)]
    public bool ArbitraryBoundedBytesNeverEscapeFormatBoundary(byte[] bytes)
    {
        if (bytes.Length > 4096)
        {
            bytes = bytes[..4096];
        }

        try
        {
            using var vault = VaultFileCodec.Decode(bytes, "Synthetic-Master-Password!42");
            return false;
        }
        catch (VaultFormatException)
        {
            return true;
        }
    }
}

