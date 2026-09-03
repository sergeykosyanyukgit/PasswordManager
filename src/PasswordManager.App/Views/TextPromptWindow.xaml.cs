using System.Windows;

namespace PasswordManager.App.Views;

public partial class TextPromptWindow : CaptureProtectedWindow
{
    public TextPromptWindow(string prompt, string initialValue = "")
    {
        InitializeComponent();
        Prompt.Text = prompt;
        Input.Text = initialValue;
        Loaded += (_, _) =>
        {
            Input.Focus();
            Input.SelectAll();
        };
    }

    public string Value => Input.Text.Trim();

    private void AcceptClick(object sender, RoutedEventArgs eventArgs)
    {
        if (IsCaptureProtectionVerified && !string.IsNullOrWhiteSpace(Input.Text))
        {
            DialogResult = true;
            Close();
        }
    }
}

