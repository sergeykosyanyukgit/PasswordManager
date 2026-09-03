namespace PasswordManager.Security;

public readonly record struct VaultCryptoParameters(int MemoryKiB, int Iterations, int Parallelism)
{
    public const int DefaultMemoryKiB = 65_536;
    public const int DefaultIterations = 3;
    public const int DefaultParallelism = 4;

    public static VaultCryptoParameters Default { get; } =
        new(DefaultMemoryKiB, DefaultIterations, DefaultParallelism);

    public void Validate()
    {
        if (MemoryKiB is < 32_768 or > 262_144 || Iterations is < 2 or > 10 || Parallelism is < 1 or > 16)
        {
            throw new VaultFormatException("The vault requests unsafe Argon2id parameters.");
        }
    }
}

