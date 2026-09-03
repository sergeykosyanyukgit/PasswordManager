using System.Collections.Specialized;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using PasswordManager.App.Infrastructure;
using PasswordManager.App.Services;
using PasswordManager.App.ViewModels;
using PasswordManager.Core.Models;
using PasswordManager.Hibp;
using PasswordManager.Security;
using PasswordManager.Storage;

namespace PasswordManager.App.Views;

public partial class MainWindow : CaptureProtectedWindow, IDisposable
{
    private readonly MainWindowViewModel viewModel = new();
    private readonly AutoLockService autoLock = new();
    private readonly IReadOnlyList<string> initialPaths;
    private CancellationTokenSource clipboardCancellation = new();

    public MainWindow(IReadOnlyList<string> initialPaths)
    {
        InitializeComponent();
        this.initialPaths = initialPaths;
        DataContext = viewModel;
        viewModel.Vaults.CollectionChanged += VaultsChanged;
        autoLock.LockRequested += (_, _) => LockAll();
        Loaded += MainWindowLoaded;
        Closing += MainWindowClosing;
    }

    public async void OpenPaths(IReadOnlyList<string> paths)
    {
        foreach (var path in paths.Take(16))
        {
            await OpenVaultAsync(path).ConfigureAwait(true);
        }
    }

    private void MainWindowLoaded(object sender, RoutedEventArgs eventArgs)
    {
        if (!IsCaptureProtectionVerified)
        {
            return;
        }

        OpenPaths(initialPaths);
    }

    private async void OpenClick(object sender, RoutedEventArgs eventArgs)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "PasswordManager vault (*.pmvault)|*.pmvault",
            CheckFileExists = true,
            Multiselect = true,
            Title = Localizer.Instance["Open"],
        };
        if (dialog.ShowDialog(this) == true)
        {
            foreach (var path in dialog.FileNames.Take(16))
            {
                await OpenVaultAsync(path).ConfigureAwait(true);
            }
        }
    }

    private async void CreateClick(object sender, RoutedEventArgs eventArgs)
    {
        var fileDialog = new SaveFileDialog
        {
            Filter = "PasswordManager vault (*.pmvault)|*.pmvault",
            AddExtension = true,
            DefaultExt = VaultRepository.VaultExtension,
            OverwritePrompt = true,
            Title = Localizer.Instance["Create"],
        };
        if (fileDialog.ShowDialog(this) != true)
        {
            return;
        }

        var passwordDialog = new PasswordPromptWindow(Path.GetFileName(fileDialog.FileName), isCreate: true) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        var masterPassword = passwordDialog.TakeMasterPassword();
        try
        {
            var session = await VaultRepository.CreateAsync(fileDialog.FileName, masterPassword).ConfigureAwait(true);
            AddSession(session);
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
        finally
        {
            masterPassword = string.Empty;
        }
    }

    private async Task OpenVaultAsync(string path)
    {
        var existing = viewModel.Vaults.FirstOrDefault(tab => string.Equals(tab.Session.Path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            viewModel.SelectedVault = existing;
            Activate();
            return;
        }

        var passwordDialog = new PasswordPromptWindow(Path.GetFileName(path), isCreate: false) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        var masterPassword = passwordDialog.TakeMasterPassword();
        try
        {
            var session = await VaultRepository.OpenAsync(path, masterPassword).ConfigureAwait(true);
            AddSession(session);
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
        finally
        {
            masterPassword = string.Empty;
        }
    }

    private async void SaveAsClick(object sender, RoutedEventArgs eventArgs)
    {
        if (viewModel.SelectedVault is not { } source)
        {
            return;
        }

        var fileDialog = new SaveFileDialog
        {
            Filter = "PasswordManager vault (*.pmvault)|*.pmvault",
            AddExtension = true,
            DefaultExt = VaultRepository.VaultExtension,
            OverwritePrompt = true,
            Title = Localizer.Instance["SaveAs"],
        };
        if (fileDialog.ShowDialog(this) != true)
        {
            return;
        }

        var passwordDialog = new PasswordPromptWindow(Path.GetFileName(fileDialog.FileName), isCreate: true) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        var masterPassword = passwordDialog.TakeMasterPassword();
        try
        {
            var clone = VaultDocumentCloner.Clone(source.Session.Document);
            var newSession = await VaultRepository.CreateAsync(fileDialog.FileName, masterPassword, clone).ConfigureAwait(true);
            AddSession(newSession);
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
        finally
        {
            masterPassword = string.Empty;
        }
    }

    private async void ChangeMasterPasswordClick(object sender, RoutedEventArgs eventArgs)
    {
        if (viewModel.SelectedVault is not { } tab)
        {
            return;
        }

        var passwordDialog = new PasswordPromptWindow(tab.Title + " — new master password", isCreate: true) { Owner = this };
        if (passwordDialog.ShowDialog() != true)
        {
            return;
        }

        var masterPassword = passwordDialog.TakeMasterPassword();
        try
        {
            await VaultRepository.ChangeMasterPasswordAsync(tab.Session, masterPassword).ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
        finally
        {
            masterPassword = string.Empty;
        }
    }

    private void AddSession(VaultSession session)
    {
        var tab = new VaultTabViewModel(session);
        viewModel.Vaults.Add(tab);
        viewModel.SelectedVault = tab;
        autoLock.TimeoutMinutes = viewModel.Vaults.Min(item => item.Session.Document.Settings.AutoLockMinutes);
    }

    private async void AddFolderClick(object sender, RoutedEventArgs eventArgs)
    {
        if (((FrameworkElement)sender).DataContext is not VaultTabViewModel tab)
        {
            return;
        }

        var dialog = new TextPromptWindow(Localizer.Instance["AddFolder"]) { Owner = this };
        if (dialog.ShowDialog() == true)
        {
            try
            {
                await tab.AddFolderAsync(dialog.Value).ConfigureAwait(true);
            }
            catch (Exception exception)
            {
                ShowSafeError(exception);
            }
        }
    }

    private void AddRecordClick(object sender, RoutedEventArgs eventArgs)
    {
        if (((FrameworkElement)sender).DataContext is VaultTabViewModel tab)
        {
            tab.NewRecord();
        }
    }

    private async void SaveRecordClick(object sender, RoutedEventArgs eventArgs)
    {
        if (FindVaultTab(sender) is not { } tab)
        {
            return;
        }

        var compromisedOverride = false;
        if (tab.Draft?.IsCompromised == true)
        {
            compromisedOverride = MessageBox.Show(
                tab.Draft.BreachMessage + "\n\nSave this password anyway?",
                Localizer.Instance["Compromised"],
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) == MessageBoxResult.Yes;
            if (!compromisedOverride)
            {
                return;
            }
        }

        try
        {
            await tab.SaveDraftAsync(compromisedOverride).ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
    }

    private void CancelRecordClick(object sender, RoutedEventArgs eventArgs) => FindVaultTab(sender)?.CancelDraft();

    private async void DeleteRecordClick(object sender, RoutedEventArgs eventArgs)
    {
        if (((FrameworkElement)sender).DataContext is not VaultTabViewModel tab || tab.SelectedRecord is null)
        {
            return;
        }

        var permanent = tab.ShowRecycleBin;
        if (permanent && MessageBox.Show(
                "Permanent removal cannot guarantee physical erasure from SSD sectors. Continue?",
                Localizer.Instance["Delete"],
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            await tab.DeleteSelectedRecordAsync(permanent).ConfigureAwait(true);
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
    }

    private void GeneratePasswordClick(object sender, RoutedEventArgs eventArgs) => FindVaultTab(sender)?.GeneratePassword();

    private void GeneratePassphraseClick(object sender, RoutedEventArgs eventArgs) => FindVaultTab(sender)?.GeneratePassphrase();

    private void AddCustomFieldClick(object sender, RoutedEventArgs eventArgs) => FindVaultTab(sender)?.AddCustomField();

    private void RemoveCustomFieldClick(object sender, RoutedEventArgs eventArgs)
    {
        if (((FrameworkElement)sender).DataContext is CustomField field)
        {
            FindVaultTab(sender)?.RemoveCustomField(field);
        }
    }

    private async void CheckPasswordClick(object sender, RoutedEventArgs eventArgs)
    {
        if (FindVaultTab(sender) is not { } tab)
        {
            return;
        }

        var consent = tab.Session.Document.Settings.HibpConsent || MessageBox.Show(
            "Have I Been Pwned will receive only the first five SHA-1 hex characters with response padding. The password and full hash are never sent. Allow this check for this vault?",
            "Have I Been Pwned",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No) == MessageBoxResult.Yes;

        try
        {
            var result = await tab.CheckPasswordAsync(consent).ConfigureAwait(true);
            if (result.Status == PwnedPasswordStatus.Compromised)
            {
                MessageBox.Show(tab.Draft?.BreachMessage, Localizer.Instance["Compromised"], MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
    }

    private async void CopyPasswordClick(object sender, RoutedEventArgs eventArgs)
    {
        if (FindVaultTab(sender) is not { Draft.Password.Length: > 0 } tab)
        {
            return;
        }

        clipboardCancellation.Cancel();
        clipboardCancellation.Dispose();
        clipboardCancellation = new CancellationTokenSource();
        try
        {
            await SecureClipboardService.CopyAsync(
                tab.Draft.Password,
                TimeSpan.FromSeconds(Math.Clamp(tab.Session.Document.Settings.ClipboardClearSeconds, 5, 300)),
                clipboardCancellation.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            // A newer copy owns the conditional clearing timer.
        }
    }

    private async void ConnectSshClick(object sender, RoutedEventArgs eventArgs)
    {
        if (FindVaultTab(sender) is not { Draft.Type: SecretRecordType.Ssh, Draft.Ssh: not null } tab)
        {
            return;
        }

        var terminal = new TerminalWindow(tab.Draft.Ssh, async () => await tab.PersistAsync().ConfigureAwait(true)) { Owner = this };
        terminal.Show();
    }

    private void FolderSelected(object sender, RoutedPropertyChangedEventArgs<object> eventArgs)
    {
        if (((FrameworkElement)sender).DataContext is VaultTabViewModel tab && eventArgs.NewValue is FolderNodeViewModel folder)
        {
            tab.SelectedFolder = folder;
        }
    }

    private async void RenameFolderClick(object sender, RoutedEventArgs eventArgs)
    {
        if (viewModel.SelectedVault is not { SelectedFolder: { } folder } tab || folder.Id == tab.Session.Document.RootFolderId)
        {
            return;
        }

        var dialog = new TextPromptWindow("Rename folder", folder.Name) { Owner = this };
        if (dialog.ShowDialog() == true)
        {
            folder.Name = dialog.Value;
            try
            {
                await tab.PersistAsync().ConfigureAwait(true);
            }
            catch (Exception exception)
            {
                ShowSafeError(exception);
            }
        }
    }

    private void FolderKeyDown(object sender, KeyEventArgs eventArgs)
    {
        if (eventArgs.Key == Key.F2)
        {
            RenameFolderClick(sender, eventArgs);
            eventArgs.Handled = true;
        }
    }

    private void RecordMouseMove(object sender, MouseEventArgs eventArgs)
    {
        if (eventArgs.LeftButton == MouseButtonState.Pressed && ((FrameworkElement)sender).DataContext is VaultTabViewModel { SelectedRecord: { } record })
        {
            _ = DragDrop.DoDragDrop((DependencyObject)sender, record.Id.ToString("D"), DragDropEffects.Move);
        }
    }

    private async void FolderDrop(object sender, DragEventArgs eventArgs)
    {
        if (((FrameworkElement)sender).DataContext is not VaultTabViewModel tab ||
            !eventArgs.Data.GetDataPresent(DataFormats.StringFormat) ||
            !Guid.TryParse(eventArgs.Data.GetData(DataFormats.StringFormat) as string, out var recordId))
        {
            return;
        }

        var tree = (TreeView)sender;
        var element = tree.InputHitTest(eventArgs.GetPosition(tree)) as DependencyObject;
        var item = ItemsControl.ContainerFromElement(tree, element) as TreeViewItem;
        if (item?.DataContext is not FolderNodeViewModel target ||
            tab.Session.Document.Records.FirstOrDefault(record => record.Id == recordId) is not { } record)
        {
            return;
        }

        record.FolderId = target.Id;
        try
        {
            await tab.PersistAsync().ConfigureAwait(true);
            tab.SelectedFolder = target;
        }
        catch (Exception exception)
        {
            ShowSafeError(exception);
        }
    }

    private void WindowDrop(object sender, DragEventArgs eventArgs)
    {
        if (eventArgs.Data.GetDataPresent(DataFormats.FileDrop) && eventArgs.Data.GetData(DataFormats.FileDrop) is string[] files)
        {
            OpenPaths(files.Where(path => path.EndsWith(VaultRepository.VaultExtension, StringComparison.OrdinalIgnoreCase)).ToArray());
        }
    }

    private void LanguageClick(object sender, RoutedEventArgs eventArgs)
    {
        if (sender is MenuItem { Tag: string language })
        {
            Localizer.Instance.SetLanguage(language);
        }
    }

    private void LockAllClick(object sender, RoutedEventArgs eventArgs) => LockAll();

    private void LockAll()
    {
        foreach (Window window in Application.Current.Windows.Cast<Window>().Where(window => window != this).ToArray())
        {
            window.Close();
        }

        foreach (var tab in viewModel.Vaults.ToArray())
        {
            tab.Dispose();
        }

        viewModel.Vaults.Clear();
        viewModel.SelectedVault = null;
        clipboardCancellation.Cancel();
    }

    private void MainWindowClosing(object? sender, System.ComponentModel.CancelEventArgs eventArgs)
    {
        if (viewModel.Vaults.Any(tab => tab.Draft is not null) && MessageBox.Show(
                "Unsaved editor drafts will be discarded. Confirm lock and exit?",
                Localizer.Instance["AppTitle"],
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            eventArgs.Cancel = true;
            return;
        }

        autoLock.Dispose();
        LockAll();
        clipboardCancellation.Dispose();
    }

    private void VaultsChanged(object? sender, NotifyCollectionChangedEventArgs eventArgs)
    {
        var hasVault = viewModel.Vaults.Count > 0;
        EmptyState.Visibility = hasVault ? Visibility.Collapsed : Visibility.Visible;
        VaultTabs.Visibility = hasVault ? Visibility.Visible : Visibility.Collapsed;
    }

    private void NotifyActivity(object sender, MouseEventArgs eventArgs) => autoLock.NotifyActivity();

    private void WindowPreviewKeyDown(object sender, KeyEventArgs eventArgs)
    {
        autoLock.NotifyActivity();
        if (eventArgs.Key == Key.Delete && viewModel.SelectedVault?.SelectedRecord is not null)
        {
            DeleteRecordClick(VaultTabs, eventArgs);
        }
    }

    private static VaultTabViewModel? FindVaultTab(object sender)
    {
        var element = sender as FrameworkElement;
        while (element is not null)
        {
            if (element.DataContext is VaultTabViewModel tab)
            {
                return tab;
            }

            element = element.Parent as FrameworkElement;
        }

        return (Application.Current.MainWindow?.DataContext as MainWindowViewModel)?.SelectedVault;
    }

    private static void ShowSafeError(Exception exception)
    {
        var message = exception switch
        {
            VaultAuthenticationException => "Wrong master password or vault authentication failed.",
            VaultFormatException => "The vault format is invalid, unsupported, or damaged. The source was not changed.",
            VaultLockedException => "The vault is already open for writing or its lock is unavailable.",
            VaultConflictException => "The vault changed outside this session. It was not overwritten; use Save As.",
            AtomicReplaceNotSupportedException => "This filesystem cannot safely replace the vault. The source was not changed; use Save As.",
            CompromisedPasswordConfirmationRequiredException => "A compromised password requires explicit confirmation.",
            IOException => "The storage operation failed. Confirmed changes remain only in memory until a safe save succeeds.",
            _ => "The operation failed safely.",
        };
        MessageBox.Show(message, Localizer.Instance["AppTitle"], MessageBoxButton.OK, MessageBoxImage.Error);
    }

    public void Dispose()
    {
        autoLock.Dispose();
        clipboardCancellation.Dispose();
        GC.SuppressFinalize(this);
    }
}
