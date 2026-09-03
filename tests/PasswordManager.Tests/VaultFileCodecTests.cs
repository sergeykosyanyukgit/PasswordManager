using System.Buffers.Binary;
using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Security;

namespace PasswordManager.Tests;

public sealed class VaultFileCodecTests
{
    private const string MasterPassword = "Synthetic-Master-Password!42";

    [Fact]
    public void RoundTripPreservesSecretDocument()
    {
        var document = CreateDocument();
        using var unlocked = VaultFileCodec.CreateNew(MasterPassword, document);
        var encoded = VaultFileCodec.Encode(document, unlocked);

        using var reopened = VaultFileCodec.Decode(encoded, MasterPassword);

        var record = Assert.Single(reopened.Document.Records);
        Assert.Equal("Synthetic login", record.Name);
        Assert.Equal("Synthetic-Record-Password!42", record.Password);
        Assert.Equal(unlocked.VaultId, reopened.VaultId);
    }

    [Fact]
    public void NfcEquivalentMasterPasswordsUnlockSameVault()
    {
        var composed = string.Concat(Enumerable.Repeat("é", 15));
        var decomposed = string.Concat(Enumerable.Repeat("e\u0301", 15));
        using var unlocked = VaultFileCodec.CreateNew(composed, CreateDocument());
        var encoded = VaultFileCodec.Encode(unlocked.Document, unlocked);

        using var reopened = VaultFileCodec.Decode(encoded, decomposed);

        Assert.Single(reopened.Document.Records);
    }

    [Fact]
    public void WrongMasterPasswordIsGenericAuthenticationFailure()
    {
        using var unlocked = VaultFileCodec.CreateNew(MasterPassword, CreateDocument());
        var encoded = VaultFileCodec.Encode(unlocked.Document, unlocked);

        Assert.Throws<VaultAuthenticationException>(() =>
            VaultFileCodec.Decode(encoded, "Synthetic-Wrong-Password!42"));
    }

    [Fact]
    public void EveryHeaderByteMutationIsRejected()
    {
        using var unlocked = VaultFileCodec.CreateNew(MasterPassword, CreateDocument());
        var encoded = VaultFileCodec.Encode(unlocked.Document, unlocked);

        for (var index = 0; index < VaultFileCodec.HeaderSize; index++)
        {
            var changed = (byte[])encoded.Clone();
            changed[index] ^= 0x80;
            Assert.ThrowsAny<VaultFormatException>(() => VaultFileCodec.Decode(changed, MasterPassword));
        }
    }

    [Fact]
    public void AuthenticatedPayloadMutationIsRejected()
    {
        using var unlocked = VaultFileCodec.CreateNew(MasterPassword, CreateDocument());
        var encoded = VaultFileCodec.Encode(unlocked.Document, unlocked);
        encoded[^1] ^= 0x01;

        Assert.Throws<VaultAuthenticationException>(() => VaultFileCodec.Decode(encoded, MasterPassword));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(219)]
    public void TruncationIsRejected(int length)
    {
        var truncated = new byte[length];
        Assert.Throws<VaultFormatException>(() => VaultFileCodec.Decode(truncated, MasterPassword));
    }

    [Fact]
    public void UnsafeKdfMemoryIsRejectedBeforeDerivation()
    {
        using var unlocked = VaultFileCodec.CreateNew(MasterPassword, CreateDocument());
        var encoded = VaultFileCodec.Encode(unlocked.Document, unlocked);
        BinaryPrimitives.WriteInt32LittleEndian(encoded.AsSpan(32, 4), int.MaxValue);
        SHA256.HashData(encoded.AsSpan(0, 188), encoded.AsSpan(188, 32));

        Assert.Throws<VaultFormatException>(() => VaultFileCodec.Decode(encoded, MasterPassword));
    }

    [Fact]
    public void MasterPasswordChangeRotatesKdfAndRejectsOldPassword()
    {
        using var original = VaultFileCodec.CreateNew(MasterPassword, CreateDocument());
        using var changed = VaultFileCodec.ChangeMasterPassword(original, "Synthetic-New-Master-Password!43");
        var encoded = VaultFileCodec.Encode(changed.Document, changed);

        Assert.Throws<VaultAuthenticationException>(() => VaultFileCodec.Decode(encoded, MasterPassword));
        using var reopened = VaultFileCodec.Decode(encoded, "Synthetic-New-Master-Password!43");
        Assert.Single(reopened.Document.Records);
    }

    private static VaultDocument CreateDocument()
    {
        var document = VaultDocument.CreateEmpty();
        document.Records.Add(new VaultRecord
        {
            FolderId = document.RootFolderId,
            Type = SecretRecordType.Login,
            Name = "Synthetic login",
            UserName = "synthetic-user",
            Password = "Synthetic-Record-Password!42",
            Url = "https://example.invalid/",
        });
        return document;
    }
}

