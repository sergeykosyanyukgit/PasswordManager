using System.Collections.ObjectModel;
using System.Net;
using System.Net.Http;
using PasswordManager.App.Infrastructure;
using PasswordManager.Core.Models;
using PasswordManager.Hibp;
using PasswordManager.Security;
using PasswordManager.Storage;

namespace PasswordManager.App.ViewModels;

public sealed class VaultTabViewModel : ObservableObject, IDisposable
{
    private readonly HttpClient hibpHttpClient;
    private readonly PwnedPasswordClient pwnedPasswordClient;
    private FolderNodeViewModel? selectedFolder;
    private VaultRecord? selectedRecord;
    private RecordDraftViewModel? draft;
    private string searchText = string.Empty;
    private bool showRecycleBin;
    private bool busy;
    private readonly Array recordTypes = Enum.GetValues<SecretRecordType>();

    public VaultTabViewModel(VaultSession session)
    {
        Session = session;
        hibpHttpClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        })
        {
            BaseAddress = PwnedPasswordClient.ServiceBaseAddress,
            Timeout = TimeSpan.FromSeconds(10),
        };
        hibpHttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PasswordManager/1.0");
        pwnedPasswordClient = new PwnedPasswordClient(hibpHttpClient);
        RebuildFolders();
    }

    public VaultSession Session { get; }

    public string Title => Session.DisplayName;

    public ObservableCollection<FolderNodeViewModel> FolderRoots { get; } = [];

    public ObservableCollection<VaultRecord> VisibleRecords { get; } = [];

    public Array RecordTypes => recordTypes;

    public FolderNodeViewModel? SelectedFolder
    {
        get => selectedFolder;
        set
        {
            if (SetProperty(ref selectedFolder, value))
            {
                OnPropertyChanged(nameof(Breadcrumb));
                RefreshRecords();
            }
        }
    }

    public VaultRecord? SelectedRecord
    {
        get => selectedRecord;
        set
        {
            if (SetProperty(ref selectedRecord, value))
            {
                Draft = value is null ? null : RecordDraftViewModel.FromRecord(value);
            }
        }
    }

    public RecordDraftViewModel? Draft { get => draft; set => SetProperty(ref draft, value); }

    public string SearchText
    {
        get => searchText;
        set
        {
            if (SetProperty(ref searchText, value))
            {
                RefreshRecords();
            }
        }
    }

    public bool ShowRecycleBin
    {
        get => showRecycleBin;
        set
        {
            if (SetProperty(ref showRecycleBin, value))
            {
                RebuildFolders();
            }
        }
    }

    public bool IsBusy { get => busy; private set => SetProperty(ref busy, value); }

    public string Breadcrumb
    {
        get
        {
            if (SelectedFolder is null)
            {
                return string.Empty;
            }

            var names = new Stack<string>();
            var current = SelectedFolder.Folder;
            var byId = Session.Document.Folders.ToDictionary(folder => folder.Id);
            while (true)
            {
                names.Push(current.Name);
                if (current.ParentId is not Guid parentId || !byId.TryGetValue(parentId, out current!))
                {
                    break;
                }
            }

            return string.Join(" › ", names);
        }
    }

    public void NewRecord(SecretRecordType type = SecretRecordType.Login)
    {
        if (SelectedFolder is null || ShowRecycleBin)
        {
            return;
        }

        SelectedRecord = null;
        Draft = new RecordDraftViewModel
        {
            Type = type,
            Ssh = type == SecretRecordType.Ssh ? new SshProfile() : null,
        };
    }

    public async Task AddFolderAsync(string name)
    {
        if (SelectedFolder is null || ShowRecycleBin || string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        Session.Document.Folders.Add(new VaultFolder
        {
            ParentId = SelectedFolder.Id,
            Name = name.Trim(),
        });
        await PersistAsync().ConfigureAwait(true);
        RebuildFolders();
    }

    public async Task SaveDraftAsync(bool compromisedOverride)
    {
        if (Draft is null || SelectedFolder is null || string.IsNullOrWhiteSpace(Draft.Name))
        {
            throw new InvalidOperationException("A record name is required.");
        }

        if (Draft.IsCompromised && !compromisedOverride)
        {
            throw new CompromisedPasswordConfirmationRequiredException();
        }

        var record = Draft.ExistingId is Guid id
            ? Session.Document.Records.Single(candidate => candidate.Id == id)
            : new VaultRecord { FolderId = SelectedFolder.Id };
        record.Name = Draft.Name.Trim();
        record.Type = Draft.Type;
        record.UserName = Draft.UserName;
        record.Email = Draft.Email;
        record.Password = Draft.Password;
        record.Url = Draft.Url;
        record.Notes = Draft.Notes;
        record.Ssh = Draft.Ssh;
        record.CustomFields = Draft.CustomFields.ToList();
        record.ModifiedUtc = DateTimeOffset.UtcNow;
        record.Breach.CompromisedSaveConfirmed = Draft.IsCompromised && compromisedOverride;
        record.Breach.Status = Draft.BreachStatus;
        record.Breach.OccurrenceCount = Draft.BreachOccurrenceCount;
        record.Breach.CheckedUtc = Draft.BreachCheckedUtc;

        if (Draft.ExistingId is null)
        {
            Session.Document.Records.Add(record);
        }

        await PersistAsync().ConfigureAwait(true);
        RefreshRecords();
        SelectedRecord = record;
    }

    public async Task DeleteSelectedRecordAsync(bool permanent)
    {
        if (SelectedRecord is null)
        {
            return;
        }

        if (permanent)
        {
            _ = Session.Document.Records.Remove(SelectedRecord);
        }
        else
        {
            SelectedRecord.IsDeleted = true;
            SelectedRecord.DeletedUtc = DateTimeOffset.UtcNow;
        }

        SelectedRecord = null;
        await PersistAsync().ConfigureAwait(true);
        RefreshRecords();
    }

    public async Task RestoreSelectedRecordAsync()
    {
        if (SelectedRecord is null || !SelectedRecord.IsDeleted)
        {
            return;
        }

        SelectedRecord.IsDeleted = false;
        SelectedRecord.DeletedUtc = null;
        await PersistAsync().ConfigureAwait(true);
        SelectedRecord = null;
        RefreshRecords();
    }

    public void CancelDraft()
    {
        Draft = SelectedRecord is null ? null : RecordDraftViewModel.FromRecord(SelectedRecord);
    }

    public void GeneratePassword()
    {
        if (Draft is not null)
        {
            Draft.Password = PasswordGenerator.GeneratePassword(new PasswordGenerationOptions());
        }
    }

    public void GeneratePassphrase()
    {
        if (Draft is not null)
        {
            Draft.Password = PasswordGenerator.GeneratePassphrase();
        }
    }

    public void AddCustomField()
    {
        Draft?.CustomFields.Add(new CustomField { Name = "Field" });
    }

    public void RemoveCustomField(CustomField field)
    {
        ArgumentNullException.ThrowIfNull(field);
        _ = Draft?.CustomFields.Remove(field);
    }

    public async Task<PwnedPasswordResult> CheckPasswordAsync(bool consentGranted)
    {
        if (Draft is null || string.IsNullOrEmpty(Draft.Password))
        {
            throw new InvalidOperationException("Enter a completed password before checking it.");
        }

        if (!Session.Document.Settings.HibpConsent)
        {
            if (!consentGranted)
            {
                return PwnedPasswordResult.Failed("ConsentRequired");
            }

            Session.Document.Settings.HibpConsent = true;
            await PersistAsync().ConfigureAwait(true);
        }

        IsBusy = true;
        try
        {
            var result = await pwnedPasswordClient.CheckAsync(Draft.Password).ConfigureAwait(true);
            Draft.IsCompromised = result.Status == PwnedPasswordStatus.Compromised;
            Draft.BreachStatus = result.Status switch
            {
                PwnedPasswordStatus.Compromised => BreachCheckStatus.Compromised,
                PwnedPasswordStatus.NotFound => BreachCheckStatus.SafeAtCheckTime,
                _ => BreachCheckStatus.Failed,
            };
            Draft.BreachOccurrenceCount = result.OccurrenceCount;
            Draft.BreachCheckedUtc = DateTimeOffset.UtcNow;
            Draft.BreachMessage = result.Status switch
            {
                PwnedPasswordStatus.Compromised => $"{Localizer.Instance["Compromised"]}: {result.OccurrenceCount:N0}",
                PwnedPasswordStatus.NotFound => "HIBP: not found at check time",
                _ => "HIBP: not checked (network or service failure)",
            };

            if (Draft.ExistingId is Guid id)
            {
                var record = Session.Document.Records.Single(candidate => candidate.Id == id);
                record.Breach.Status = result.Status switch
                {
                    PwnedPasswordStatus.Compromised => BreachCheckStatus.Compromised,
                    PwnedPasswordStatus.NotFound => BreachCheckStatus.SafeAtCheckTime,
                    _ => BreachCheckStatus.Failed,
                };
                record.Breach.OccurrenceCount = result.OccurrenceCount;
                record.Breach.CheckedUtc = DateTimeOffset.UtcNow;
            }

            return result;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task PersistAsync()
    {
        IsBusy = true;
        try
        {
            await VaultRepository.SaveAsync(Session).ConfigureAwait(true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void Dispose()
    {
        hibpHttpClient.Dispose();
        ClearSensitiveModel();
        Session.Dispose();
    }

    private void ClearSensitiveModel()
    {
        if (Draft is not null)
        {
            Draft.Name = string.Empty;
            Draft.UserName = string.Empty;
            Draft.Email = string.Empty;
            Draft.Password = string.Empty;
            Draft.Url = string.Empty;
            Draft.Notes = string.Empty;
            ClearSsh(Draft.Ssh);
            ClearCustomFields(Draft.CustomFields);
            Draft = null;
        }

        foreach (var record in Session.Document.Records)
        {
            record.Name = string.Empty;
            record.UserName = string.Empty;
            record.Email = string.Empty;
            record.Password = string.Empty;
            record.Url = string.Empty;
            record.Notes = string.Empty;
            ClearSsh(record.Ssh);
            ClearCustomFields(record.CustomFields);
        }

        foreach (var folder in Session.Document.Folders)
        {
            folder.Name = string.Empty;
        }

        SelectedRecord = null;
        SelectedFolder = null;
        VisibleRecords.Clear();
        FolderRoots.Clear();
        Session.Document.Records.Clear();
        Session.Document.Folders.Clear();
    }

    private static void ClearSsh(SshProfile? profile)
    {
        if (profile is null)
        {
            return;
        }

        profile.Host = string.Empty;
        profile.UserName = string.Empty;
        profile.Password = string.Empty;
        profile.PrivateKeyPem = string.Empty;
        profile.PrivateKeyPassphrase = string.Empty;
        profile.HostKeySha256 = string.Empty;
    }

    private static void ClearCustomFields(IEnumerable<CustomField> fields)
    {
        foreach (var field in fields)
        {
            field.Name = string.Empty;
            field.Value = string.Empty;
        }
    }

    private void RebuildFolders()
    {
        var selectedId = SelectedFolder?.Id ?? Session.Document.RootFolderId;
        FolderRoots.Clear();
        var included = Session.Document.Folders
            .Where(folder => folder.IsDeleted == ShowRecycleBin)
            .ToDictionary(folder => folder.Id, folder => new FolderNodeViewModel(folder));

        if (!ShowRecycleBin && included.TryGetValue(Session.Document.RootFolderId, out var root))
        {
            PopulateChildren(root, included);
            FolderRoots.Add(root);
            SelectedFolder = FindNode(root, selectedId) ?? root;
        }
        else
        {
            foreach (var node in included.Values.OrderBy(node => node.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                FolderRoots.Add(node);
            }

            SelectedFolder = FolderRoots.FirstOrDefault();
        }

        RefreshRecords();
    }

    private void PopulateChildren(FolderNodeViewModel parent, IReadOnlyDictionary<Guid, FolderNodeViewModel> nodes)
    {
        foreach (var child in Session.Document.Folders
                     .Where(folder => !folder.IsDeleted && folder.ParentId == parent.Id)
                     .OrderBy(folder => folder.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var node = nodes[child.Id];
            parent.Children.Add(node);
            PopulateChildren(node, nodes);
        }
    }

    private void RefreshRecords()
    {
        VisibleRecords.Clear();
        if (SelectedFolder is null)
        {
            return;
        }

        foreach (var record in Session.Document.Records
                     .Where(record => record.IsDeleted == ShowRecycleBin)
                     .Where(record => ShowRecycleBin || record.FolderId == SelectedFolder.Id)
                     .Where(record => string.IsNullOrWhiteSpace(SearchText) ||
                         record.Name.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ||
                         record.UserName.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ||
                         record.Email.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase))
                     .OrderBy(record => record.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            VisibleRecords.Add(record);
        }
    }

    private static FolderNodeViewModel? FindNode(FolderNodeViewModel root, Guid id)
    {
        if (root.Id == id)
        {
            return root;
        }

        foreach (var child in root.Children)
        {
            var result = FindNode(child, id);
            if (result is not null)
            {
                return result;
            }
        }

        return null;
    }
}

public sealed class CompromisedPasswordConfirmationRequiredException : Exception;
