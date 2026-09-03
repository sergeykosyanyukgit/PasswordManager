using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace PasswordManager.Tests;

public sealed class CryptographicVectorTests
{
    [Fact]
    public void Argon2idMatchesRfc9106Section53()
    {
        var password = Enumerable.Repeat((byte)0x01, 32).ToArray();
        var salt = Enumerable.Repeat((byte)0x02, 16).ToArray();
        var secret = Enumerable.Repeat((byte)0x03, 8).ToArray();
        var associated = Enumerable.Repeat((byte)0x04, 12).ToArray();
        var expected = Convert.FromHexString("0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659");
        var output = new byte[32];
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(32)
            .WithIterations(3)
            .WithParallelism(4)
            .WithSalt(salt)
            .WithSecret(secret)
            .WithAdditional(associated)
            .Build();

        try
        {
            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);
            _ = generator.GenerateBytes(password, output);
            Assert.Equal(expected, output);
        }
        finally
        {
            parameters.Clear();
            CryptographicOperations.ZeroMemory(password);
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(output);
        }
    }

    [Fact]
    public void HkdfSha256MatchesRfc5869TestCase1()
    {
        var inputKey = Enumerable.Repeat((byte)0x0B, 22).ToArray();
        var salt = Convert.FromHexString("000102030405060708090A0B0C");
        var info = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9");
        var expected = Convert.FromHexString("3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865");
        var output = new byte[42];

        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKey, output, salt, info);

        Assert.Equal(expected, output);
    }

    [Fact]
    public void Aes256GcmMatchesNistEmptyAadVector()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var plaintext = new byte[16];
        var ciphertext = new byte[16];
        var tag = new byte[16];

        using var cipher = new AesGcm(key, 16);
        cipher.Encrypt(nonce, plaintext, ciphertext, tag);

        Assert.Equal(Convert.FromHexString("CEA7403D4D606B6E074EC5D3BAF39D18"), ciphertext);
        Assert.Equal(Convert.FromHexString("D0D1C8A799996BF0265B98B5D48AB919"), tag);
    }
}

