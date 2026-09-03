using System.Windows;
using System.Windows.Controls;

namespace PasswordManager.App.Infrastructure;

public static class PasswordBoxAssistant
{
    public static readonly DependencyProperty BoundPasswordProperty = DependencyProperty.RegisterAttached(
        "BoundPassword",
        typeof(string),
        typeof(PasswordBoxAssistant),
        new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnBoundPasswordChanged));

    public static readonly DependencyProperty BindPasswordProperty = DependencyProperty.RegisterAttached(
        "BindPassword",
        typeof(bool),
        typeof(PasswordBoxAssistant),
        new PropertyMetadata(false, OnBindPasswordChanged));

    private static readonly DependencyProperty UpdatingProperty = DependencyProperty.RegisterAttached(
        "Updating",
        typeof(bool),
        typeof(PasswordBoxAssistant));

    public static string GetBoundPassword(DependencyObject value) => (string)value.GetValue(BoundPasswordProperty);

    public static void SetBoundPassword(DependencyObject value, string password) => value.SetValue(BoundPasswordProperty, password);

    public static bool GetBindPassword(DependencyObject value) => (bool)value.GetValue(BindPasswordProperty);

    public static void SetBindPassword(DependencyObject value, bool enabled) => value.SetValue(BindPasswordProperty, enabled);

    private static void OnBindPasswordChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs eventArgs)
    {
        if (dependencyObject is not PasswordBox passwordBox)
        {
            return;
        }

        passwordBox.PasswordChanged -= PasswordChanged;
        if (eventArgs.NewValue is true)
        {
            passwordBox.PasswordChanged += PasswordChanged;
        }
    }

    private static void OnBoundPasswordChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs eventArgs)
    {
        if (dependencyObject is not PasswordBox passwordBox || (bool)passwordBox.GetValue(UpdatingProperty))
        {
            return;
        }

        passwordBox.Password = eventArgs.NewValue as string ?? string.Empty;
    }

    private static void PasswordChanged(object sender, RoutedEventArgs eventArgs)
    {
        var passwordBox = (PasswordBox)sender;
        passwordBox.SetValue(UpdatingProperty, true);
        SetBoundPassword(passwordBox, passwordBox.Password);
        passwordBox.SetValue(UpdatingProperty, false);
    }
}

