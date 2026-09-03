using System.Collections.ObjectModel;
using PasswordManager.App.Infrastructure;
using PasswordManager.Core.Models;

namespace PasswordManager.App.ViewModels;

public sealed class FolderNodeViewModel(VaultFolder folder) : ObservableObject
{
    public VaultFolder Folder { get; } = folder;

    public Guid Id => Folder.Id;

    public string Name
    {
        get => Folder.Name;
        set
        {
            if (!string.Equals(Folder.Name, value, StringComparison.Ordinal))
            {
                Folder.Name = value;
                OnPropertyChanged();
            }
        }
    }

    public ObservableCollection<FolderNodeViewModel> Children { get; } = [];
}

