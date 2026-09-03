using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Security;

namespace PasswordManager.Storage;

public static class VaultRepository
{
    public const string VaultExtension = ".pmvault";

    public static async Task<VaultSession> OpenAsync(string path, string masterPassword, CancellationToken cancellationToken = default)
    {
        var canonicalPath = ValidateVaultPath(path, mustExist: true);
        var writerLock = AcquireWriterLock(canonicalPath);
        try
        {
            var bytes = await ReadBoundedAsync(canonicalPath, cancellationToken).ConfigureAwait(false);
            try
            {
                var unlocked = VaultFileCodec.Decode(bytes, masterPassword);
                var hash = SHA256.HashData(bytes);
                CleanupEncryptedTemporaryFiles(canonicalPath);
                return new VaultSession(canonicalPath, writerLock, hash, unlocked);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch
        {
            var lockPath = writerLock.Name;
            await writerLock.DisposeAsync().ConfigureAwait(false);
            TryDelete(lockPath);
            throw;
        }
    }

    public static async Task<VaultSession> CreateAsync(
        string path,
        string masterPassword,
        VaultDocument? initialDocument = null,
        CancellationToken cancellationToken = default)
    {
        var canonicalPath = ValidateVaultPath(path, mustExist: false);
        if (File.Exists(canonicalPath))
        {
            throw new IOException("The destination vault already exists.");
        }

        var writerLock = AcquireWriterLock(canonicalPath);
        UnlockedVault? unlocked = null;
        try
        {
            unlocked = VaultFileCodec.CreateNew(masterPassword, initialDocument ?? VaultDocument.CreateEmpty());
            var bytes = VaultFileCodec.Encode(unlocked.Document, unlocked);
            try
            {
                await CreateNewAtomicallyAsync(canonicalPath, bytes, cancellationToken).ConfigureAwait(false);
                var verified = await ReadBoundedAsync(canonicalPath, cancellationToken).ConfigureAwait(false);
                try
                {
                    _ = VaultFileCodec.VerifyAndDecode(verified, unlocked);
                    var hash = SHA256.HashData(verified);
                    return new VaultSession(canonicalPath, writerLock, hash, unlocked);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(verified);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        catch
        {
            unlocked?.Dispose();
            var lockPath = writerLock.Name;
            await writerLock.DisposeAsync().ConfigureAwait(false);
            TryDelete(lockPath);
            throw;
        }
    }

    public static async Task SaveAsync(VaultSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        session.MarkChanged();
        await SaveWithMaterialAsync(session, session.UnlockedVault, cancellationToken).ConfigureAwait(false);
    }

    public static async Task ChangeMasterPasswordAsync(
        VaultSession session,
        string newMasterPassword,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        var replacement = VaultFileCodec.ChangeMasterPassword(session.UnlockedVault, newMasterPassword);
        try
        {
            session.MarkChanged();
            await SaveWithMaterialAsync(session, replacement, cancellationToken).ConfigureAwait(false);
            session.ReplaceUnlockedVault(replacement);
        }
        catch
        {
            replacement.Dispose();
            throw;
        }
    }

    private static async Task SaveWithMaterialAsync(
        VaultSession session,
        UnlockedVault material,
        CancellationToken cancellationToken)
    {
        session.EnsureWriterLock();
        var bytes = VaultFileCodec.Encode(session.Document, material);
        var tempPath = CreateTempPath(session.Path);

        try
        {
            await WriteDurablyAsync(tempPath, bytes, cancellationToken).ConfigureAwait(false);
            var reread = await ReadBoundedAsync(tempPath, cancellationToken).ConfigureAwait(false);
            try
            {
                _ = VaultFileCodec.VerifyAndDecode(reread, material);
                if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(reread), SHA256.HashData(bytes)))
                {
                    throw new IOException("The encrypted temporary file did not verify byte-for-byte.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(reread);
            }

            var current = await ReadBoundedAsync(session.Path, cancellationToken).ConfigureAwait(false);
            try
            {
                var currentHash = SHA256.HashData(current);
                if (!CryptographicOperations.FixedTimeEquals(currentHash, session.SourceHash))
                {
                    throw new VaultConflictException("The vault changed outside this session. It was not overwritten.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(current);
            }

            try
            {
                File.Replace(tempPath, session.Path, destinationBackupFileName: null, ignoreMetadataErrors: false);
            }
            catch (Exception exception) when (exception is IOException or PlatformNotSupportedException or UnauthorizedAccessException)
            {
                throw new AtomicReplaceNotSupportedException(
                    "The filesystem did not provide a safe atomic replacement. Use Save As.",
                    exception);
            }

            session.UpdateSourceHash(SHA256.HashData(bytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            TryDelete(tempPath);
        }
    }

    public static IReadOnlyList<string> FindEncryptedTemporaryFiles(string vaultPath)
    {
        var canonicalPath = ValidateVaultPath(vaultPath, mustExist: false);
        var directory = System.IO.Path.GetDirectoryName(canonicalPath)
            ?? throw new ArgumentException("The vault path has no parent directory.", nameof(vaultPath));
        var prefix = System.IO.Path.GetFileName(canonicalPath) + ".";
        var results = new List<string>();
        Span<byte> magic = stackalloc byte[8];

        foreach (var candidate in Directory.EnumerateFiles(directory, prefix + "*.tmp", SearchOption.TopDirectoryOnly).Take(32))
        {
            try
            {
                using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.Read);
                magic.Clear();
                if (stream.Read(magic) == magic.Length && magic.SequenceEqual("PMVAULT1"u8))
                {
                    results.Add(candidate);
                }
            }
            catch (IOException)
            {
                // Ignore a temp that is still in use or disappeared during enumeration.
            }
        }

        return results;
    }

    internal static FileStream AcquireWriterLock(string vaultPath)
    {
        var lockPath = vaultPath + ".lock";
        try
        {
            var stream = new FileStream(
                lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.WriteThrough);
            stream.Flush(flushToDisk: true);
            return stream;
        }
        catch (IOException exception)
        {
            throw new VaultLockedException("The vault is already open for writing or the lock is unavailable.", exception);
        }
    }

    private static async Task CreateNewAtomicallyAsync(string destination, byte[] bytes, CancellationToken cancellationToken)
    {
        var tempPath = CreateTempPath(destination);
        try
        {
            await WriteDurablyAsync(tempPath, bytes, cancellationToken).ConfigureAwait(false);
            File.Move(tempPath, destination, overwrite: false);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static async Task WriteDurablyAsync(string path, byte[] bytes, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
    }

    private static async Task<byte[]> ReadBoundedAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        if (stream.Length is < VaultFileCodec.HeaderSize or > VaultFileCodec.MaximumFileSize)
        {
            throw new VaultFormatException("The vault file size is invalid.");
        }

        var bytes = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    private static string ValidateVaultPath(string path, bool mustExist)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var canonical = System.IO.Path.GetFullPath(path);
        if (!canonical.EndsWith(VaultExtension, StringComparison.OrdinalIgnoreCase))
        {
            canonical += VaultExtension;
        }

        if (mustExist && !File.Exists(canonical))
        {
            throw new FileNotFoundException("The vault does not exist.", canonical);
        }

        var directory = System.IO.Path.GetDirectoryName(canonical);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException("The vault directory does not exist.");
        }

        return canonical;
    }

    private static string CreateTempPath(string vaultPath) =>
        vaultPath + "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)) + ".tmp";

    private static void CleanupEncryptedTemporaryFiles(string vaultPath)
    {
        foreach (var tempPath in FindEncryptedTemporaryFiles(vaultPath))
        {
            TryDelete(tempPath);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // The caller still receives the primary failure; orphan recovery can handle this encrypted temp.
        }
        catch (UnauthorizedAccessException)
        {
            // The encrypted temp contains no plaintext and is discoverable for recovery on next launch.
        }
    }
}

public sealed class VaultLockedException(string message, Exception? innerException = null) : IOException(message, innerException);

public sealed class VaultConflictException(string message) : IOException(message);

public sealed class AtomicReplaceNotSupportedException(string message, Exception innerException) : IOException(message, innerException);
