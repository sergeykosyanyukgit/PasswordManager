using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace PasswordManager.Security;

public static class MasterKeyDeriver
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static SecureBuffer Derive(string masterPassword, ReadOnlySpan<byte> salt, VaultCryptoParameters parameters)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);
        parameters.Validate();
        if (salt.Length != VaultFileCodec.KdfSaltSize)
        {
            throw new ArgumentException("The Argon2id salt must be 16 bytes.", nameof(salt));
        }

        var normalized = masterPassword.Normalize(NormalizationForm.FormC);
        byte[]? passwordBytes = null;
        var root = new byte[VaultFileCodec.KeySize];

        try
        {
            passwordBytes = StrictUtf8.GetBytes(normalized);
            var builder = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithIterations(parameters.Iterations)
                .WithMemoryAsKB(parameters.MemoryKiB)
                .WithParallelism(parameters.Parallelism)
                .WithSalt(salt.ToArray());

            var argonParameters = builder.Build();
            var generator = new Argon2BytesGenerator();
            generator.Init(argonParameters);
            _ = generator.GenerateBytes(passwordBytes, root);
            var secureBuffer = SecureBuffer.Create(root);
            if (OperatingSystem.IsWindows() && !secureBuffer.IsMemoryLocked)
            {
                secureBuffer.Dispose();
                throw new CryptographicException("The derived key could not be locked in memory.");
            }

            return secureBuffer;
        }
        finally
        {
            if (passwordBytes is not null)
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }

            CryptographicOperations.ZeroMemory(root);
        }
    }
}
