using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Windows.ApplicationModel.DataTransfer;

namespace PasswordManager.App.Services;

public static class SecureClipboardService
{
    public static async Task CopyAsync(string value, TimeSpan clearAfter, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(value);
        var expectedHash = HashText(value);
        var package = new DataPackage();
        package.SetText(value);
        if (!Clipboard.SetContentWithOptions(
                package,
                new ClipboardContentOptions
                {
                    IsAllowedInHistory = false,
                    IsRoamable = false,
                }))
        {
            CryptographicOperations.ZeroMemory(expectedHash);
            throw new InvalidOperationException("Windows rejected the protected clipboard options.");
        }
        Clipboard.Flush();
        value = string.Empty;

        try
        {
            await Task.Delay(clearAfter, cancellationToken).ConfigureAwait(false);
            var view = Clipboard.GetContent();
            if (view.Contains(StandardDataFormats.Text))
            {
                var current = await view.GetTextAsync();
                var currentHash = HashText(current);
                current = string.Empty;
                try
                {
                    if (CryptographicOperations.FixedTimeEquals(currentHash, expectedHash))
                    {
                        Clipboard.Clear();
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(currentHash);
                }
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or COMException)
        {
            // Clipboard ownership changed or is temporarily unavailable; never clear another owner's value.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private static byte[] HashText(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
