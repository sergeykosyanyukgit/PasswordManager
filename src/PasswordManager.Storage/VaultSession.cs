using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Security;

namespace PasswordManager.Storage;

public sealed class VaultSession : IAsyncDisposable, IDisposable
{
    private FileStream? writerLock;
    private byte[] sourceHash;
    private bool disposed;

    internal VaultSession(string path, FileStream writerLock, byte[] sourceHash, UnlockedVault unlockedVault)
    {
        Path = path;
        this.writerLock = writerLock;
        this.sourceHash = sourceHash;
        UnlockedVault = unlockedVault;
    }

    public string Path { get; }

    public string DisplayName => System.IO.Path.GetFileNameWithoutExtension(Path);

    public VaultDocument Document => UnlockedVault.Document;

    public bool HasUnsavedChanges { get; internal set; }

    public bool IsMemoryLocked => UnlockedVault.IsMemoryLocked;

    internal UnlockedVault UnlockedVault { get; private set; }

    internal ReadOnlySpan<byte> SourceHash => sourceHash;

    internal void UpdateSourceHash(byte[] hash)
    {
        CryptographicOperations.ZeroMemory(sourceHash);
        sourceHash = hash;
        HasUnsavedChanges = false;
    }

    internal void ReplaceUnlockedVault(UnlockedVault replacement)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        var previous = UnlockedVault;
        UnlockedVault = replacement;
        previous.Dispose();
    }

    public void MarkChanged()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Document.ModifiedUtc = DateTimeOffset.UtcNow;
        HasUnsavedChanges = true;
    }

    internal void EnsureWriterLock()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (writerLock is null)
        {
            writerLock = VaultRepository.AcquireWriterLock(Path);
            return;
        }

        try
        {
            _ = writerLock.Length;
            writerLock.Flush(flushToDisk: true);
        }
        catch (IOException)
        {
            writerLock?.Dispose();
            writerLock = VaultRepository.AcquireWriterLock(Path);
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        UnlockedVault.Dispose();
        CryptographicOperations.ZeroMemory(sourceHash);
        var lockPath = writerLock?.Name;
        writerLock?.Dispose();
        writerLock = null;
        TryDeleteLock(lockPath);
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private static void TryDeleteLock(string? lockPath)
    {
        if (string.IsNullOrEmpty(lockPath))
        {
            return;
        }

        try
        {
            File.Delete(lockPath);
        }
        catch (IOException)
        {
            // A stale, empty lock file is harmless; the live handle is the authority.
        }
        catch (UnauthorizedAccessException)
        {
            // The live handle has already been released. Do not mask vault shutdown.
        }
    }
}
