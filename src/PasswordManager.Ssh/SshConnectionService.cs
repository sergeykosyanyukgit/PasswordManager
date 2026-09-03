using System.Security.Cryptography;
using System.Text;
using PasswordManager.Core.Models;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace PasswordManager.Ssh;

public sealed class SshConnectionService
{
    private static readonly HashSet<string> AllowedEncryptions = new(StringComparer.Ordinal)
    {
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
    };

    private static readonly HashSet<string> AllowedKeyExchanges = new(StringComparer.Ordinal)
    {
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp521",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
    };

    private static readonly HashSet<string> AllowedMacs = new(StringComparer.Ordinal)
    {
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256",
    };

    private static readonly HashSet<string> AllowedHostKeys = new(StringComparer.Ordinal)
    {
        "ssh-ed25519",
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256",
    };

    public static async Task<SshTerminalSession> ConnectAsync(
        SshProfile profile,
        Func<string, bool> confirmFirstUseFingerprint,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(confirmFirstUseFingerprint);
        ValidateProfile(profile);

        var resources = new List<IDisposable>();
        try
        {
            var authentication = CreateAuthentication(profile, resources);
            var connection = new ConnectionInfo(profile.Host, profile.Port, profile.UserName, authentication)
            {
                Timeout = TimeSpan.FromSeconds(20),
                RetryAttempts = 1,
            };
            ApplyAlgorithmPolicy(connection);

            var client = new SshClient(connection);
            resources.Add(client);
            client.HostKeyReceived += (_, eventArgs) =>
            {
                var fingerprint = FormatFingerprint(eventArgs.HostKey);
                if (!string.IsNullOrWhiteSpace(profile.HostKeySha256))
                {
                    eventArgs.CanTrust = CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(fingerprint),
                        Encoding.ASCII.GetBytes(profile.HostKeySha256));
                    return;
                }

                eventArgs.CanTrust = confirmFirstUseFingerprint(fingerprint);
                if (eventArgs.CanTrust)
                {
                    profile.HostKeySha256 = fingerprint;
                }
            };

            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
            if (!client.IsConnected)
            {
                throw new SshConnectionException("SSH connection failed.");
            }

            var shell = client.CreateShellStream(
                "xterm-256color",
                columns: 80,
                rows: 24,
                width: 800,
                height: 600,
                bufferSize: 1024 * 1024);
            resources.Add(shell);
            return new SshTerminalSession(client, shell, resources);
        }
        catch
        {
            foreach (var resource in resources.AsEnumerable().Reverse())
            {
                resource.Dispose();
            }

            throw;
        }
    }

    public static void ApplyAlgorithmPolicy(ConnectionInfo connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        RetainAllowed(connection.Encryptions, AllowedEncryptions, "encryption");
        RetainAllowed(connection.KeyExchangeAlgorithms, AllowedKeyExchanges, "key exchange");
        RetainAllowed(connection.HmacAlgorithms, AllowedMacs, "message authentication");
        RetainAllowed(connection.HostKeyAlgorithms, AllowedHostKeys, "host key");
    }

    private static AuthenticationMethod[] CreateAuthentication(SshProfile profile, List<IDisposable> resources)
    {
        if (profile.AuthenticationKind == SshAuthenticationKind.Password)
        {
            return [new PasswordAuthenticationMethod(profile.UserName, profile.Password)];
        }

        var keyBytes = Encoding.UTF8.GetBytes(profile.PrivateKeyPem);
        try
        {
            var keyStream = new MemoryStream(keyBytes, writable: false);
            resources.Add(keyStream);
            var privateKey = string.IsNullOrEmpty(profile.PrivateKeyPassphrase)
                ? new PrivateKeyFile(keyStream)
                : new PrivateKeyFile(keyStream, profile.PrivateKeyPassphrase);
            resources.Add(privateKey);
            return [new PrivateKeyAuthenticationMethod(profile.UserName, privateKey)];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    private static void RetainAllowed<T>(IDictionary<string, T> algorithms, HashSet<string> allowed, string category)
    {
        foreach (var name in algorithms.Keys.Where(name => !allowed.Contains(name)).ToArray())
        {
            _ = algorithms.Remove(name);
        }

        if (algorithms.Count == 0)
        {
            throw new SshConnectionException($"No approved SSH {category} algorithm is available.");
        }
    }

    private static string FormatFingerprint(byte[] hostKey)
    {
        var digest = SHA256.HashData(hostKey);
        try
        {
            return "SHA256:" + Convert.ToBase64String(digest).TrimEnd('=');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static void ValidateProfile(SshProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Host) || string.IsNullOrWhiteSpace(profile.UserName) || profile.Port is < 1 or > 65535)
        {
            throw new ArgumentException("The SSH host, port, or user name is invalid.", nameof(profile));
        }

        if (profile.AuthenticationKind == SshAuthenticationKind.PrivateKey && string.IsNullOrWhiteSpace(profile.PrivateKeyPem))
        {
            throw new ArgumentException("A private key is required for private-key authentication.", nameof(profile));
        }
    }
}

public sealed class SshTerminalSession : IAsyncDisposable, IDisposable
{
    private readonly SshClient client;
    private readonly ShellStream shell;
    private readonly IReadOnlyList<IDisposable> resources;
    private bool disposed;

    internal SshTerminalSession(SshClient client, ShellStream shell, IReadOnlyList<IDisposable> resources)
    {
        this.client = client;
        this.shell = shell;
        this.resources = resources;
    }

    public Stream InputOutput => shell;

    public bool IsConnected => !disposed && client.IsConnected;

    public void Resize(uint columns, uint rows, uint width, uint height)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (columns is < 1 or > 1000 || rows is < 1 or > 1000 || width > 10000 || height > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(columns), "Terminal dimensions are outside safe bounds.");
        }

        shell.ChangeWindowSize(columns, rows, width, height);
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        foreach (var resource in resources.Reverse())
        {
            resource.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed class SshConnectionException(string message) : Exception(message);
