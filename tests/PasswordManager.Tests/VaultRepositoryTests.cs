using PasswordManager.Core.Models;
using PasswordManager.Storage;

namespace PasswordManager.Tests;

public sealed class VaultRepositoryTests : IDisposable
{
    private const string MasterPassword = "Synthetic-Master-Password!42";
    private readonly string directory = Path.Combine(Path.GetTempPath(), "PasswordManager.Tests." + Guid.NewGuid().ToString("N"));

    public VaultRepositoryTests()
    {
        Directory.CreateDirectory(directory);
    }

    [Fact]
    public async Task CreateSaveReopenUsesOneVaultFileAndRemovesLock()
    {
        var path = Path.Combine(directory, "roundtrip.pmvault");
        await using (var session = await VaultRepository.CreateAsync(path, MasterPassword))
        {
            session.Document.Records.Add(new VaultRecord
            {
                FolderId = session.Document.RootFolderId,
                Name = "Synthetic note",
                Type = SecretRecordType.SecureNote,
                Notes = "Synthetic content only",
            });
            await VaultRepository.SaveAsync(session);
        }

        Assert.False(File.Exists(path + ".lock"));
        Assert.Single(Directory.EnumerateFiles(directory, "*.pmvault"));

        await using var reopened = await VaultRepository.OpenAsync(path, MasterPassword);
        Assert.Single(reopened.Document.Records);
    }

    [Fact]
    public async Task SecondWriterIsRejected()
    {
        var path = Path.Combine(directory, "writer-lock.pmvault");
        await using var first = await VaultRepository.CreateAsync(path, MasterPassword);

        await Assert.ThrowsAsync<VaultLockedException>(() => VaultRepository.OpenAsync(path, MasterPassword));
    }

    [Fact]
    public async Task ExternalChangeIsNeverOverwritten()
    {
        var path = Path.Combine(directory, "conflict.pmvault");
        await using var session = await VaultRepository.CreateAsync(path, MasterPassword);
        var externalBytes = await File.ReadAllBytesAsync(path);
        externalBytes[^1] ^= 0x01;
        await File.WriteAllBytesAsync(path, externalBytes);
        session.Document.Folders[0].Name = "Synthetic changed name";

        await Assert.ThrowsAsync<VaultConflictException>(() => VaultRepository.SaveAsync(session));
        Assert.Equal(externalBytes, await File.ReadAllBytesAsync(path));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }

        GC.SuppressFinalize(this);
    }
}

