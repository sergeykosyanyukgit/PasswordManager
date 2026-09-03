using System.Text;
using PasswordManager.Core.Models;

namespace PasswordManager.Core.Validation;

public static class VaultValidator
{
    public const int MaximumFolderDepth = 64;
    public const int MaximumNameLength = 512;
    public const int MaximumFieldLength = 16 * 1024 * 1024;
    public const int MaximumFolders = 100_000;
    public const int MaximumRecords = 1_000_000;
    public const int MaximumCustomFieldsPerRecord = 256;

    public static void Validate(VaultDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        if (document.Folders.Count is < 1 or > MaximumFolders)
        {
            throw new VaultValidationException("The vault contains an invalid number of folders.");
        }

        if (document.Records.Count > MaximumRecords)
        {
            throw new VaultValidationException("The vault contains too many records.");
        }

        var folders = new Dictionary<Guid, VaultFolder>();
        foreach (var folder in document.Folders)
        {
            ValidateName(folder.Name, "folder");
            if (folder.Id == Guid.Empty || !folders.TryAdd(folder.Id, folder))
            {
                throw new VaultValidationException("Folder identifiers must be unique and non-empty.");
            }
        }

        if (!folders.TryGetValue(document.RootFolderId, out var root) || root.ParentId is not null)
        {
            throw new VaultValidationException("The vault root folder is invalid.");
        }

        foreach (var folder in document.Folders)
        {
            ValidateFolderAncestry(folder, folders);
        }

        var recordIds = new HashSet<Guid>();
        foreach (var record in document.Records)
        {
            if (record.Id == Guid.Empty || !recordIds.Add(record.Id))
            {
                throw new VaultValidationException("Record identifiers must be unique and non-empty.");
            }

            if (!folders.ContainsKey(record.FolderId))
            {
                throw new VaultValidationException("A record references a missing folder.");
            }

            ValidateName(record.Name, "record");
            ValidateField(record.UserName);
            ValidateField(record.Email);
            ValidateField(record.Password);
            ValidateField(record.Url);
            ValidateField(record.Notes);

            if (record.CustomFields.Count > MaximumCustomFieldsPerRecord)
            {
                throw new VaultValidationException("A record has too many custom fields.");
            }

            foreach (var field in record.CustomFields)
            {
                ValidateName(field.Name, "custom field");
                ValidateField(field.Value);
            }

            ValidateSsh(record.Ssh);
        }
    }

    private static void ValidateFolderAncestry(VaultFolder folder, Dictionary<Guid, VaultFolder> folders)
    {
        var visited = new HashSet<Guid>();
        var current = folder;
        var depth = 0;

        while (current.ParentId is Guid parentId)
        {
            if (!visited.Add(current.Id) || !folders.TryGetValue(parentId, out current!))
            {
                throw new VaultValidationException("The folder tree contains a cycle or missing parent.");
            }

            if (++depth > MaximumFolderDepth)
            {
                throw new VaultValidationException("The folder tree exceeds the depth limit.");
            }
        }
    }

    private static void ValidateSsh(SshProfile? ssh)
    {
        if (ssh is null)
        {
            return;
        }

        ValidateField(ssh.Host);
        ValidateField(ssh.UserName);
        ValidateField(ssh.Password);
        ValidateField(ssh.PrivateKeyPem);
        ValidateField(ssh.PrivateKeyPassphrase);
        ValidateField(ssh.HostKeySha256);

        if (ssh.Port is < 1 or > 65535)
        {
            throw new VaultValidationException("The SSH port is invalid.");
        }
    }

    private static void ValidateName(string value, string kind)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaximumNameLength || HasInvalidUnicode(value))
        {
            throw new VaultValidationException($"The {kind} name is invalid.");
        }
    }

    private static void ValidateField(string value)
    {
        if (value.Length > MaximumFieldLength || HasInvalidUnicode(value))
        {
            throw new VaultValidationException("A record field is invalid or too large.");
        }
    }

    private static bool HasInvalidUnicode(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (char.IsHighSurrogate(value[index]))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index]))
                {
                    return true;
                }
            }
            else if (char.IsLowSurrogate(value[index]))
            {
                return true;
            }
        }

        return false;
    }
}

public sealed class VaultValidationException(string message) : Exception(message);
