using System.Collections.ObjectModel;
using PasswordManager.App.Infrastructure;

namespace PasswordManager.App.ViewModels;

public sealed class MainWindowViewModel : ObservableObject
{
    private VaultTabViewModel? selectedVault;

    public ObservableCollection<VaultTabViewModel> Vaults { get; } = [];

    public VaultTabViewModel? SelectedVault { get => selectedVault; set => SetProperty(ref selectedVault, value); }
}

