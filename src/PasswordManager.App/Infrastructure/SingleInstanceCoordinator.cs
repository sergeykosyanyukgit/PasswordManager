using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace PasswordManager.App.Infrastructure;

internal sealed class SingleInstanceCoordinator : IDisposable
{
    private const int MaximumMessageBytes = 64 * 1024;
    private readonly CancellationTokenSource cancellation = new();
    private readonly string pipeName;
    private readonly Mutex mutex;
    private bool ownsMutex;
    private Task? serverTask;

    public SingleInstanceCoordinator()
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        var identityHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid)))[..24];
        pipeName = "PasswordManager-" + identityHash;
        mutex = new Mutex(initiallyOwned: false, "Local\\PasswordManager-" + identityHash);
    }

    public event EventHandler<IReadOnlyList<string>>? PathsReceived;

    public bool TryBecomePrimary(IReadOnlyList<string> initialPaths)
    {
        try
        {
            ownsMutex = mutex.WaitOne(0, exitContext: false);
        }
        catch (AbandonedMutexException)
        {
            ownsMutex = true;
        }

        if (!ownsMutex)
        {
            SendToPrimaryAsync(initialPaths, CancellationToken.None).GetAwaiter().GetResult();
            return false;
        }

        serverTask = RunServerAsync(cancellation.Token);
        return true;
    }

    public void Dispose()
    {
        cancellation.Cancel();
        try
        {
            serverTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // Shutdown must not surface a pipe cancellation error.
        }

        if (ownsMutex)
        {
            mutex.ReleaseMutex();
        }

        mutex.Dispose();
        cancellation.Dispose();
    }

    private async Task RunServerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var pipe = new NamedPipeServerStream(
                pipeName,
                PipeDirection.In,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: MaximumMessageBytes,
                outBufferSize: 1);

            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                var message = await ReadBoundedMessageAsync(pipe, cancellationToken).ConfigureAwait(false);
                var paths = JsonSerializer.Deserialize<string[]>(message) ?? [];
                var accepted = paths
                    .Take(16)
                    .Where(path => path.Length <= 4096)
                    .Select(Path.GetFullPath)
                    .Where(path => path.EndsWith(PasswordManager.Storage.VaultRepository.VaultExtension, StringComparison.OrdinalIgnoreCase))
                    .Where(File.Exists)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                if (accepted.Length > 0)
                {
                    PathsReceived?.Invoke(this, accepted);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is IOException or JsonException or ArgumentException)
            {
                // Untrusted local messages are ignored without logging their content.
            }
        }
    }

    private async Task SendToPrimaryAsync(IReadOnlyList<string> paths, CancellationToken cancellationToken)
    {
        await using var pipe = new NamedPipeClientStream(
            serverName: ".",
            pipeName,
            PipeDirection.Out,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        var message = JsonSerializer.SerializeToUtf8Bytes(paths.Take(16));
        if (message.Length > MaximumMessageBytes)
        {
            throw new IOException("The single-instance message is too large.");
        }

        await pipe.WriteAsync(message, timeout.Token).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadBoundedMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return memory.ToArray();
            }

            if (memory.Length + read > MaximumMessageBytes)
            {
                throw new IOException("The single-instance message is too large.");
            }

            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }
}
