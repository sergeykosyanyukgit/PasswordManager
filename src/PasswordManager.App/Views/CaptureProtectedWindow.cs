using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using PasswordManager.App.Infrastructure;

namespace PasswordManager.App.Views;

public abstract partial class CaptureProtectedWindow : Window
{
    private const uint WdaExcludeFromCapture = 0x00000011;

    public bool IsCaptureProtectionVerified { get; private set; }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var handle = new WindowInteropHelper(this).Handle;
        IsCaptureProtectionVerified = handle != IntPtr.Zero &&
            NativeMethods.SetWindowDisplayAffinity(handle, WdaExcludeFromCapture) &&
            NativeMethods.GetWindowDisplayAffinity(handle, out var actual) &&
            actual == WdaExcludeFromCapture;

        if (!IsCaptureProtectionVerified)
        {
            Visibility = Visibility.Hidden;
            MessageBox.Show(
                Localizer.Instance["SecurityError"] + ": WDA_EXCLUDEFROMCAPTURE",
                Localizer.Instance["AppTitle"],
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Close();
        }
    }

    private static partial class NativeMethods
    {
        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool SetWindowDisplayAffinity(IntPtr window, uint affinity);

        [LibraryImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static partial bool GetWindowDisplayAffinity(IntPtr window, out uint affinity);
    }
}
