using System.Windows;
using PasswordManager.App.Infrastructure;
using PasswordManager.Core.Validation;

namespace PasswordManager.App.Views;

public partial class PasswordPromptWindow : CaptureProtectedWindow
{
    private readonly bool isCreate;

    public PasswordPromptWindow(string vaultName, bool isCreate)
    {
        InitializeComponent();
        this.isCreate = isCreate;
        PromptText.Text = isCreate
            ? $"{Localizer.Instance["Create"]}: {vaultName}"
            : $"{Localizer.Instance["Unlock"]}: {vaultName}";
        ConfirmationPanel.Visibility = isCreate ? Visibility.Visible : Visibility.Collapsed;
        AcceptButton.Content = isCreate ? Localizer.Instance["Create"] : Localizer.Instance["Unlock"];
    }

    public string MasterPassword { get; private set; } = string.Empty;

    public string TakeMasterPassword()
    {
        var value = MasterPassword;
        MasterPassword = string.Empty;
        PasswordInput.Clear();
        ConfirmationInput.Clear();
        return value;
    }

    private void AcceptClick(object sender, RoutedEventArgs eventArgs)
    {
        if (!IsCaptureProtectionVerified)
        {
            return;
        }

        if (isCreate)
        {
            var strength = PasswordPolicy.Evaluate(PasswordInput.Password);
            if (PasswordInput.Password.Length < PasswordPolicy.MinimumMasterPasswordLength)
            {
                PolicyMessage.Text = $"Minimum length: {PasswordPolicy.MinimumMasterPasswordLength}.";
                return;
            }

            if (!string.Equals(PasswordInput.Password, ConfirmationInput.Password, StringComparison.Ordinal))
            {
                PolicyMessage.Text = "Passwords do not match.";
                return;
            }

            if (strength.Score < 2)
            {
                PolicyMessage.Text = "Choose a stronger master password.";
                return;
            }
        }

        MasterPassword = PasswordInput.Password;
        DialogResult = true;
        Close();
    }
}

