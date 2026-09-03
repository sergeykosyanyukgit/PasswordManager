namespace PasswordManager.Core.Models;

public static class VaultDocumentCloner
{
    public static VaultDocument Clone(VaultDocument source)
    {
        ArgumentNullException.ThrowIfNull(source);
        return new VaultDocument
        {
            RootFolderId = source.RootFolderId,
            ModifiedUtc = source.ModifiedUtc,
            Settings = new VaultSettings
            {
                HibpConsent = source.Settings.HibpConsent,
                ClipboardClearSeconds = source.Settings.ClipboardClearSeconds,
                AutoLockMinutes = source.Settings.AutoLockMinutes,
                SessionLanguage = source.Settings.SessionLanguage,
            },
            Folders = source.Folders.Select(folder => new VaultFolder
            {
                Id = folder.Id,
                ParentId = folder.ParentId,
                Name = folder.Name,
                IsDeleted = folder.IsDeleted,
                DeletedUtc = folder.DeletedUtc,
            }).ToList(),
            Records = source.Records.Select(CloneRecord).ToList(),
        };
    }

    private static VaultRecord CloneRecord(VaultRecord record) => new()
    {
        Id = record.Id,
        FolderId = record.FolderId,
        Type = record.Type,
        Name = record.Name,
        UserName = record.UserName,
        Email = record.Email,
        Password = record.Password,
        Url = record.Url,
        Notes = record.Notes,
        IsDeleted = record.IsDeleted,
        DeletedUtc = record.DeletedUtc,
        ModifiedUtc = record.ModifiedUtc,
        Ssh = record.Ssh is null ? null : new SshProfile
        {
            Host = record.Ssh.Host,
            Port = record.Ssh.Port,
            UserName = record.Ssh.UserName,
            AuthenticationKind = record.Ssh.AuthenticationKind,
            Password = record.Ssh.Password,
            PrivateKeyPem = record.Ssh.PrivateKeyPem,
            PrivateKeyPassphrase = record.Ssh.PrivateKeyPassphrase,
            HostKeySha256 = record.Ssh.HostKeySha256,
        },
        CustomFields = record.CustomFields.Select(field => new CustomField
        {
            Name = field.Name,
            Value = field.Value,
            IsSecret = field.IsSecret,
        }).ToList(),
        Breach = new PasswordBreachState
        {
            Status = record.Breach.Status,
            OccurrenceCount = record.Breach.OccurrenceCount,
            CheckedUtc = record.Breach.CheckedUtc,
            CompromisedSaveConfirmed = record.Breach.CompromisedSaveConfirmed,
        },
    };
}

