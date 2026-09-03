using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PasswordManager.Core.Models;
using PasswordManager.Core.Validation;

namespace PasswordManager.Security;

public static class VaultFileCodec
{
    public const int MaximumFileSize = 256 * 1024 * 1024;
    public const int MaximumJsonSize = 64 * 1024 * 1024;
    public const int HeaderSize = 220;
    public const int KdfSaltSize = 16;
    public const int WrapSaltSize = 32;
    public const int NonceSize = 12;
    public const int KeySize = 32;
    public const int TagSize = 16;
    public const ushort CurrentVersion = 1;
    public const ushort CurrentCipherSuite = 1;

    private const int VersionOffset = 8;
    private const int CipherSuiteOffset = 10;
    private const int HeaderLengthOffset = 12;
    private const int VaultIdOffset = 16;
    private const int MemoryOffset = 32;
    private const int IterationsOffset = 36;
    private const int ParallelismOffset = 40;
    private const int KdfSaltOffset = 44;
    private const int WrapSaltOffset = 60;
    private const int WrapNonceOffset = 92;
    private const int WrappedKeyOffset = 104;
    private const int WrapTagOffset = 136;
    private const int PayloadNonceOffset = 152;
    private const int CiphertextLengthOffset = 164;
    private const int PayloadTagOffset = 172;
    private const int HeaderDigestOffset = 188;
    private const int WrapAadLength = 104;
    private const int PayloadAadLength = 188;

    private static readonly byte[] Magic = "PMVAULT1"u8.ToArray();
    private static readonly byte[] WrapInfo = "PasswordManager/v1/data-key-wrap"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        MaxDepth = 128,
        WriteIndented = false,
    };

    public static UnlockedVault Decode(ReadOnlySpan<byte> fileBytes, string masterPassword)
    {
        var header = ParseHeader(fileBytes);
        SecureBuffer? rootKey = null;
        try
        {
            rootKey = MasterKeyDeriver.Derive(masterPassword, header.KdfSalt, header.Parameters);
            var document = DecryptDocument(fileBytes, header, rootKey);
            return new UnlockedVault(header.VaultId, header.KdfSalt, header.Parameters, document, rootKey);
        }
        catch (VaultFormatException)
        {
            rootKey?.Dispose();
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or DecoderFallbackException)
        {
            rootKey?.Dispose();
            throw new VaultAuthenticationException("The vault could not be authenticated.", exception);
        }
    }

    public static VaultDocument VerifyAndDecode(ReadOnlySpan<byte> fileBytes, UnlockedVault unlockedVault)
    {
        ArgumentNullException.ThrowIfNull(unlockedVault);
        var header = ParseHeader(fileBytes);
        if (header.VaultId != unlockedVault.VaultId ||
            !CryptographicOperations.FixedTimeEquals(header.KdfSalt, unlockedVault.KdfSalt) ||
            header.Parameters != unlockedVault.Parameters)
        {
            throw new VaultAuthenticationException("The vault metadata changed unexpectedly.");
        }

        try
        {
            return DecryptDocument(fileBytes, header, unlockedVault.RootKey);
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or DecoderFallbackException)
        {
            throw new VaultAuthenticationException("The vault could not be authenticated.", exception);
        }
    }

    public static byte[] Encode(VaultDocument document, UnlockedVault unlockedVault)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(unlockedVault);
        VaultValidator.Validate(document);

        byte[]? json = null;
        byte[]? plaintext = null;
        var rootKey = new byte[KeySize];
        var dataKey = new byte[KeySize];
        var kek = new byte[KeySize];
        var header = new byte[HeaderSize];

        try
        {
            json = JsonSerializer.SerializeToUtf8Bytes(document, SerializerOptions);
            if (json.Length > MaximumJsonSize)
            {
                throw new VaultFormatException("The serialized vault is too large.");
            }

            var plaintextLength = checked((json.Length + sizeof(int) + 4095) / 4096 * 4096);
            plaintextLength = Math.Max(4096, plaintextLength);
            if (HeaderSize + plaintextLength > MaximumFileSize)
            {
                throw new VaultFormatException("The vault exceeds the maximum file size.");
            }

            plaintext = GC.AllocateUninitializedArray<byte>(plaintextLength);
            BinaryPrimitives.WriteInt32LittleEndian(plaintext, json.Length);
            json.CopyTo(plaintext.AsSpan(sizeof(int)));
            RandomNumberGenerator.Fill(plaintext.AsSpan(sizeof(int) + json.Length));

            unlockedVault.RootKey.CopyTo(rootKey);
            RandomNumberGenerator.Fill(dataKey);
            InitializeHeader(header, unlockedVault, plaintextLength);
            HKDF.DeriveKey(HashAlgorithmName.SHA256, rootKey, kek, header.AsSpan(WrapSaltOffset, WrapSaltSize), WrapInfo);

            using (var wrapCipher = new AesGcm(kek, TagSize))
            {
                wrapCipher.Encrypt(
                    header.AsSpan(WrapNonceOffset, NonceSize),
                    dataKey,
                    header.AsSpan(WrappedKeyOffset, KeySize),
                    header.AsSpan(WrapTagOffset, TagSize),
                    header.AsSpan(0, WrapAadLength));
            }

            var ciphertext = GC.AllocateUninitializedArray<byte>(plaintextLength);
            var payloadAad = BuildPayloadAad(header);
            try
            {
                using var payloadCipher = new AesGcm(dataKey, TagSize);
                payloadCipher.Encrypt(
                    header.AsSpan(PayloadNonceOffset, NonceSize),
                    plaintext,
                    ciphertext,
                    header.AsSpan(PayloadTagOffset, TagSize),
                    payloadAad);

                SHA256.HashData(header.AsSpan(0, HeaderDigestOffset), header.AsSpan(HeaderDigestOffset, 32));
                var result = GC.AllocateUninitializedArray<byte>(HeaderSize + ciphertext.Length);
                header.CopyTo(result, 0);
                ciphertext.CopyTo(result, HeaderSize);
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payloadAad);
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }
        finally
        {
            if (json is not null)
            {
                CryptographicOperations.ZeroMemory(json);
            }

            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            CryptographicOperations.ZeroMemory(rootKey);
            CryptographicOperations.ZeroMemory(dataKey);
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(header);
        }
    }

    public static UnlockedVault CreateNew(string masterPassword, VaultDocument document)
    {
        ValidateNewMasterPassword(masterPassword);
        VaultValidator.Validate(document);
        var parameters = VaultCryptoParameters.Default;
        var salt = RandomNumberGenerator.GetBytes(KdfSaltSize);
        SecureBuffer? rootKey = null;
        try
        {
            rootKey = MasterKeyDeriver.Derive(masterPassword, salt, parameters);
            return new UnlockedVault(Guid.NewGuid(), salt, parameters, document, rootKey);
        }
        catch
        {
            rootKey?.Dispose();
            throw;
        }
    }

    public static UnlockedVault ChangeMasterPassword(UnlockedVault current, string newMasterPassword)
    {
        ArgumentNullException.ThrowIfNull(current);
        ValidateNewMasterPassword(newMasterPassword);
        var salt = RandomNumberGenerator.GetBytes(KdfSaltSize);
        SecureBuffer? rootKey = null;
        try
        {
            rootKey = MasterKeyDeriver.Derive(newMasterPassword, salt, VaultCryptoParameters.Default);
            return new UnlockedVault(current.VaultId, salt, VaultCryptoParameters.Default, current.Document, rootKey);
        }
        catch
        {
            rootKey?.Dispose();
            throw;
        }
    }

    private static VaultHeader ParseHeader(ReadOnlySpan<byte> fileBytes)
    {
        if (fileBytes.Length is < HeaderSize or > MaximumFileSize)
        {
            throw new VaultFormatException("The vault file size is invalid.");
        }

        var header = fileBytes[..HeaderSize];
        if (!header[..Magic.Length].SequenceEqual(Magic))
        {
            throw new VaultFormatException("The file is not a PasswordManager vault.");
        }

        var version = BinaryPrimitives.ReadUInt16LittleEndian(header[VersionOffset..]);
        var suite = BinaryPrimitives.ReadUInt16LittleEndian(header[CipherSuiteOffset..]);
        var headerLength = BinaryPrimitives.ReadInt32LittleEndian(header[HeaderLengthOffset..]);
        if (version != CurrentVersion || suite != CurrentCipherSuite || headerLength != HeaderSize)
        {
            throw new VaultFormatException("The vault version or cipher suite is not supported.");
        }

        Span<byte> computedDigest = stackalloc byte[32];
        SHA256.HashData(header[..HeaderDigestOffset], computedDigest);
        if (!CryptographicOperations.FixedTimeEquals(computedDigest, header.Slice(HeaderDigestOffset, 32)))
        {
            throw new VaultFormatException("The vault header is corrupt.");
        }

        var ciphertextLength = BinaryPrimitives.ReadInt64LittleEndian(header[CiphertextLengthOffset..]);
        if (ciphertextLength is < 4096 or > MaximumFileSize - HeaderSize ||
            ciphertextLength % 4096 != 0 || ciphertextLength != fileBytes.Length - HeaderSize)
        {
            throw new VaultFormatException("The ciphertext length is invalid.");
        }

        var parameters = new VaultCryptoParameters(
            BinaryPrimitives.ReadInt32LittleEndian(header[MemoryOffset..]),
            BinaryPrimitives.ReadInt32LittleEndian(header[IterationsOffset..]),
            BinaryPrimitives.ReadInt32LittleEndian(header[ParallelismOffset..]));
        parameters.Validate();

        return new VaultHeader(
            new Guid(header.Slice(VaultIdOffset, 16), bigEndian: true),
            parameters,
            header.Slice(KdfSaltOffset, KdfSaltSize).ToArray(),
            checked((int)ciphertextLength));
    }

    private static VaultDocument DecryptDocument(ReadOnlySpan<byte> fileBytes, VaultHeader parsed, SecureBuffer rootKeyBuffer)
    {
        var header = fileBytes[..HeaderSize];
        var rootKey = new byte[KeySize];
        var kek = new byte[KeySize];
        var dataKey = new byte[KeySize];
        var plaintext = new byte[parsed.CiphertextLength];
        var payloadAad = BuildPayloadAad(header);

        try
        {
            rootKeyBuffer.CopyTo(rootKey);
            HKDF.DeriveKey(HashAlgorithmName.SHA256, rootKey, kek, header.Slice(WrapSaltOffset, WrapSaltSize), WrapInfo);

            using (var wrapCipher = new AesGcm(kek, TagSize))
            {
                wrapCipher.Decrypt(
                    header.Slice(WrapNonceOffset, NonceSize),
                    header.Slice(WrappedKeyOffset, KeySize),
                    header.Slice(WrapTagOffset, TagSize),
                    dataKey,
                    header[..WrapAadLength]);
            }

            using (var payloadCipher = new AesGcm(dataKey, TagSize))
            {
                payloadCipher.Decrypt(
                    header.Slice(PayloadNonceOffset, NonceSize),
                    fileBytes[HeaderSize..],
                    header.Slice(PayloadTagOffset, TagSize),
                    plaintext,
                    payloadAad);
            }

            var jsonLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext);
            if (jsonLength is < 2 or > MaximumJsonSize || jsonLength > plaintext.Length - sizeof(int))
            {
                throw new VaultFormatException("The authenticated JSON length is invalid.");
            }

            _ = StrictUtf8.GetCharCount(plaintext, sizeof(int), jsonLength);
            var document = JsonSerializer.Deserialize<VaultDocument>(plaintext.AsSpan(sizeof(int), jsonLength), SerializerOptions)
                ?? throw new VaultFormatException("The vault payload is empty.");
            VaultValidator.Validate(document);
            return document;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(dataKey);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(payloadAad);
        }
    }

    private static void InitializeHeader(Span<byte> header, UnlockedVault unlockedVault, int ciphertextLength)
    {
        Magic.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(header[VersionOffset..], CurrentVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[CipherSuiteOffset..], CurrentCipherSuite);
        BinaryPrimitives.WriteInt32LittleEndian(header[HeaderLengthOffset..], HeaderSize);
        _ = unlockedVault.VaultId.TryWriteBytes(header.Slice(VaultIdOffset, 16), bigEndian: true, out _);
        BinaryPrimitives.WriteInt32LittleEndian(header[MemoryOffset..], unlockedVault.Parameters.MemoryKiB);
        BinaryPrimitives.WriteInt32LittleEndian(header[IterationsOffset..], unlockedVault.Parameters.Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(header[ParallelismOffset..], unlockedVault.Parameters.Parallelism);
        unlockedVault.KdfSalt.CopyTo(header[KdfSaltOffset..]);
        RandomNumberGenerator.Fill(header.Slice(WrapSaltOffset, WrapSaltSize));
        RandomNumberGenerator.Fill(header.Slice(WrapNonceOffset, NonceSize));
        RandomNumberGenerator.Fill(header.Slice(PayloadNonceOffset, NonceSize));
        BinaryPrimitives.WriteInt64LittleEndian(header[CiphertextLengthOffset..], ciphertextLength);
    }

    private static byte[] BuildPayloadAad(ReadOnlySpan<byte> header)
    {
        var aad = header[..PayloadAadLength].ToArray();
        aad.AsSpan(WrappedKeyOffset, KeySize).Clear();
        aad.AsSpan(WrapTagOffset, TagSize).Clear();
        aad.AsSpan(PayloadTagOffset, TagSize).Clear();
        return aad;
    }

    private static void ValidateNewMasterPassword(string masterPassword)
    {
        ArgumentNullException.ThrowIfNull(masterPassword);
        if (masterPassword.Normalize(NormalizationForm.FormC).Length < PasswordPolicy.MinimumMasterPasswordLength)
        {
            throw new ArgumentException("The master password is shorter than the minimum policy.", nameof(masterPassword));
        }
    }

    private sealed record VaultHeader(
        Guid VaultId,
        VaultCryptoParameters Parameters,
        byte[] KdfSalt,
        int CiphertextLength);
}

public sealed class UnlockedVault : IDisposable
{
    private bool disposed;

    internal UnlockedVault(
        Guid vaultId,
        byte[] kdfSalt,
        VaultCryptoParameters parameters,
        VaultDocument document,
        SecureBuffer rootKey)
    {
        VaultId = vaultId;
        KdfSalt = kdfSalt;
        Parameters = parameters;
        Document = document;
        RootKey = rootKey;
    }

    public Guid VaultId { get; }

    public byte[] KdfSalt { get; }

    public VaultCryptoParameters Parameters { get; }

    public VaultDocument Document { get; set; }

    internal SecureBuffer RootKey { get; }

    public bool IsMemoryLocked => RootKey.IsMemoryLocked;

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        RootKey.Dispose();
        CryptographicOperations.ZeroMemory(KdfSalt);
        Document = VaultDocument.CreateEmpty();
        GC.SuppressFinalize(this);
    }
}

public class VaultFormatException(string message, Exception? innerException = null) : Exception(message, innerException);

public sealed class VaultAuthenticationException(string message, Exception? innerException = null)
    : VaultFormatException(message, innerException);

