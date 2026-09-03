namespace PasswordManager.Core.Validation;

public static class PasswordPolicy
{
    public const int MinimumMasterPasswordLength = 15;
    public const int MinimumGeneratedPasswordLength = 15;
    public const int MaximumGeneratedPasswordLength = 128;

    public static PasswordStrength Evaluate(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length < MinimumMasterPasswordLength)
        {
            return new PasswordStrength(0, "MasterPasswordTooShort");
        }

        var classes = 0;
        classes += password.Any(char.IsLower) ? 1 : 0;
        classes += password.Any(char.IsUpper) ? 1 : 0;
        classes += password.Any(char.IsDigit) ? 1 : 0;
        classes += password.Any(character => !char.IsLetterOrDigit(character)) ? 1 : 0;

        var score = password.Length switch
        {
            >= 24 => 3,
            >= 18 => 2,
            _ => 1,
        };

        score = Math.Min(4, score + (classes >= 3 ? 1 : 0));
        return new PasswordStrength(score, score >= 3 ? "PasswordStrong" : "PasswordCouldBeStronger");
    }
}

public readonly record struct PasswordStrength(int Score, string MessageKey);

