using PasswordManager.Security;
using PasswordManager.Ssh;
using Renci.SshNet;

namespace PasswordManager.Tests;

public sealed class GeneratorAndTerminalTests
{
    [Fact]
    public void PasswordGeneratorIncludesEverySelectedClass()
    {
        var password = PasswordGenerator.GeneratePassword(new PasswordGenerationOptions(64));
        Assert.Equal(64, password.Length);
        Assert.Contains(password, char.IsLower);
        Assert.Contains(password, char.IsUpper);
        Assert.Contains(password, char.IsDigit);
        Assert.Contains(password, character => !char.IsLetterOrDigit(character));
    }

    [Fact]
    public void PassphraseContainsSixIndependentTokens()
    {
        var phrase = PasswordGenerator.GeneratePassphrase();
        Assert.Equal(6, phrase.Split('-').Length);
    }

    [Fact]
    public void Osc52ClipboardSequenceIsRemovedAcrossChunks()
    {
        var filter = new Osc52Filter();
        var first = filter.Filter("before\u001b]52;c;U3ludGhldGlj");
        var second = filter.Filter("LVRlc3Q=\aafter");
        Assert.Equal("before", first);
        Assert.Equal("after", second);
        Assert.DoesNotContain("52;", first + second, StringComparison.Ordinal);
    }

    [Fact]
    public void Osc52C1ClipboardSequenceIsRemoved()
    {
        var filter = new Osc52Filter();
        var output = filter.Filter("before\u009d52;c;U3ludGhldGlj\u009cafter");

        Assert.Equal("beforeafter", output);
    }

    [Fact]
    public void SecureBufferIsLockedOnWindowsAndCanCopyItsValue()
    {
        var source = "Synthetic secure buffer"u8.ToArray();
        var copy = new byte[source.Length];
        try
        {
            using var secureBuffer = SecureBuffer.Create(source);
            secureBuffer.CopyTo(copy);

            Assert.Equal(source, copy);
            if (OperatingSystem.IsWindows())
            {
                Assert.True(secureBuffer.IsMemoryLocked);
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(source);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(copy);
        }
    }

    [Fact]
    public void SshPolicyRemovesLegacyAlgorithms()
    {
        var connection = new ConnectionInfo(
            "example.invalid",
            22,
            "synthetic-user",
            new PasswordAuthenticationMethod("synthetic-user", "Synthetic-SSH-Password!42"));

        SshConnectionService.ApplyAlgorithmPolicy(connection);

        Assert.DoesNotContain(connection.Encryptions.Keys, name => name.Contains("cbc", StringComparison.OrdinalIgnoreCase) || name.Contains("3des", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(connection.KeyExchangeAlgorithms.Keys, name => name.EndsWith("sha1", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(connection.HostKeyAlgorithms.Keys, name => string.Equals(name, "ssh-rsa", StringComparison.Ordinal));
        Assert.All(connection.HmacAlgorithms.Keys, name => Assert.Contains("sha2", name, StringComparison.Ordinal));
    }
}
