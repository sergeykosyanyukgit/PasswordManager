using System.Collections.ObjectModel;
using PasswordManager.App.Infrastructure;
using PasswordManager.Core.Models;

namespace PasswordManager.App.ViewModels;

public sealed class RecordDraftViewModel : ObservableObject
{
    private string name = string.Empty;
    private SecretRecordType type;
    private string userName = string.Empty;
    private string email = string.Empty;
    private string password = string.Empty;
    private string url = string.Empty;
    private string notes = string.Empty;
    private string breachMessage = string.Empty;
    private bool isCompromised;
    private BreachCheckStatus breachStatus;
    private long breachOccurrenceCount;
    private DateTimeOffset? breachCheckedUtc;

    public Guid? ExistingId { get; set; }

    public string Name { get => name; set => SetProperty(ref name, value); }

    public SecretRecordType Type
    {
        get => type;
        set
        {
            if (SetProperty(ref type, value))
            {
                if (value == SecretRecordType.Ssh)
                {
                    Ssh ??= new SshProfile();
                }

                OnPropertyChanged(nameof(IsSsh));
            }
        }
    }

    public string UserName { get => userName; set => SetProperty(ref userName, value); }

    public string Email { get => email; set => SetProperty(ref email, value); }

    public string Password
    {
        get => password;
        set
        {
            if (SetProperty(ref password, value))
            {
                IsCompromised = false;
                BreachMessage = string.Empty;
                BreachStatus = BreachCheckStatus.NotChecked;
                BreachOccurrenceCount = 0;
                BreachCheckedUtc = null;
            }
        }
    }

    public string Url { get => url; set => SetProperty(ref url, value); }

    public string Notes { get => notes; set => SetProperty(ref notes, value); }

    public string BreachMessage { get => breachMessage; set => SetProperty(ref breachMessage, value); }

    public bool IsCompromised { get => isCompromised; set => SetProperty(ref isCompromised, value); }

    public BreachCheckStatus BreachStatus { get => breachStatus; set => SetProperty(ref breachStatus, value); }

    public long BreachOccurrenceCount { get => breachOccurrenceCount; set => SetProperty(ref breachOccurrenceCount, value); }

    public DateTimeOffset? BreachCheckedUtc { get => breachCheckedUtc; set => SetProperty(ref breachCheckedUtc, value); }

    public SshProfile? Ssh { get; set; }

    public ObservableCollection<CustomField> CustomFields { get; set; } = [];

    public bool IsSsh => Type == SecretRecordType.Ssh;

    public Array SshAuthenticationKinds { get; } = Enum.GetValues<SshAuthenticationKind>();

    public static RecordDraftViewModel FromRecord(VaultRecord record) => new()
    {
        ExistingId = record.Id,
        Name = record.Name,
        Type = record.Type,
        UserName = record.UserName,
        Email = record.Email,
        Password = record.Password,
        Url = record.Url,
        Notes = record.Notes,
        Ssh = record.Ssh is null ? null : CloneSsh(record.Ssh),
        CustomFields = new ObservableCollection<CustomField>(record.CustomFields.Select(field => new CustomField
        {
            Name = field.Name,
            Value = field.Value,
            IsSecret = field.IsSecret,
        })),
        IsCompromised = record.Breach.Status == BreachCheckStatus.Compromised,
        BreachStatus = record.Breach.Status,
        BreachOccurrenceCount = record.Breach.OccurrenceCount,
        BreachCheckedUtc = record.Breach.CheckedUtc,
        BreachMessage = record.Breach.Status == BreachCheckStatus.Compromised
            ? $"{Localizer.Instance["Compromised"]}: {record.Breach.OccurrenceCount:N0}"
            : string.Empty,
    };

    private static SshProfile CloneSsh(SshProfile source) => new()
    {
        Host = source.Host,
        Port = source.Port,
        UserName = source.UserName,
        AuthenticationKind = source.AuthenticationKind,
        Password = source.Password,
        PrivateKeyPem = source.PrivateKeyPem,
        PrivateKeyPassphrase = source.PrivateKeyPassphrase,
        HostKeySha256 = source.HostKeySha256,
    };
}
