using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace PasswordManager.Core.Models;

public sealed class VaultDocument
{
    public Guid RootFolderId { get; set; }

    public List<VaultFolder> Folders { get; set; } = [];

    public List<VaultRecord> Records { get; set; } = [];

    public VaultSettings Settings { get; set; } = new();

    public DateTimeOffset ModifiedUtc { get; set; } = DateTimeOffset.UtcNow;

    public static VaultDocument CreateEmpty()
    {
        var rootId = Guid.NewGuid();
        return new VaultDocument
        {
            RootFolderId = rootId,
            Folders =
            [
                new VaultFolder
                {
                    Id = rootId,
                    ParentId = null,
                    Name = "Vault",
                },
            ],
        };
    }
}

public sealed class VaultFolder
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid? ParentId { get; set; }

    public string Name { get; set; } = string.Empty;

    public bool IsDeleted { get; set; }

    public DateTimeOffset? DeletedUtc { get; set; }
}

public sealed class VaultRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid FolderId { get; set; }

    public SecretRecordType Type { get; set; }

    public string Name { get; set; } = string.Empty;

    public string UserName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public string Notes { get; set; } = string.Empty;

    public SshProfile? Ssh { get; set; }

    public List<CustomField> CustomFields { get; set; } = [];

    public PasswordBreachState Breach { get; set; } = new();

    public bool IsDeleted { get; set; }

    public DateTimeOffset? DeletedUtc { get; set; }

    public DateTimeOffset ModifiedUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class CustomField : INotifyPropertyChanged
{
    private bool isSecret;

    public string Name { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;

    public bool IsSecret
    {
        get => isSecret;
        set
        {
            if (isSecret == value)
            {
                return;
            }

            isSecret = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed class SshProfile
{
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 22;

    public string UserName { get; set; } = string.Empty;

    public SshAuthenticationKind AuthenticationKind { get; set; }

    public string Password { get; set; } = string.Empty;

    public string PrivateKeyPem { get; set; } = string.Empty;

    public string PrivateKeyPassphrase { get; set; } = string.Empty;

    public string HostKeySha256 { get; set; } = string.Empty;
}

public sealed class PasswordBreachState
{
    public BreachCheckStatus Status { get; set; }

    public long OccurrenceCount { get; set; }

    public DateTimeOffset? CheckedUtc { get; set; }

    public bool CompromisedSaveConfirmed { get; set; }
}

public sealed class VaultSettings
{
    public bool HibpConsent { get; set; }

    public int ClipboardClearSeconds { get; set; } = 30;

    public int AutoLockMinutes { get; set; } = 15;

    public string SessionLanguage { get; set; } = string.Empty;
}

public enum SecretRecordType
{
    Login = 0,
    Email = 1,
    Password = 2,
    SecureNote = 3,
    Ssh = 4,
}

public enum SshAuthenticationKind
{
    Password = 0,
    PrivateKey = 1,
}

public enum BreachCheckStatus
{
    NotChecked = 0,
    SafeAtCheckTime = 1,
    Compromised = 2,
    Failed = 3,
}

