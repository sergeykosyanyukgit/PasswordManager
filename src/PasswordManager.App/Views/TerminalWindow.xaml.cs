using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using PasswordManager.Core.Models;
using PasswordManager.Ssh;

namespace PasswordManager.App.Views;

public partial class TerminalWindow : CaptureProtectedWindow, IDisposable
{
    private static readonly Uri TerminalUri = new("https://passwordmanager.local/index.html");
    private readonly SshProfile profile;
    private readonly Func<Task> persistFingerprint;
    private readonly CancellationTokenSource cancellation = new();
    private readonly Osc52Filter osc52Filter = new();
    private SshTerminalSession? session;
    private string? webViewDataFolder;
    private bool terminalReady;
    private bool disposed;

    public TerminalWindow(SshProfile profile, Func<Task> persistFingerprint)
    {
        InitializeComponent();
        this.profile = profile;
        this.persistFingerprint = persistFingerprint;
        Loaded += TerminalLoaded;
        Closed += TerminalClosed;
    }

    private async void TerminalLoaded(object sender, RoutedEventArgs eventArgs)
    {
        if (!IsCaptureProtectionVerified)
        {
            return;
        }

        try
        {
            await InitializeWebViewAsync().ConfigureAwait(true);
            var hadFingerprint = !string.IsNullOrWhiteSpace(profile.HostKeySha256);
            session = await SshConnectionService.ConnectAsync(profile, ConfirmFingerprint, cancellation.Token).ConfigureAwait(true);
            if (!hadFingerprint && !string.IsNullOrWhiteSpace(profile.HostKeySha256))
            {
                await persistFingerprint().ConfigureAwait(true);
            }

            Status.Visibility = Visibility.Collapsed;
            WebView.Visibility = Visibility.Visible;
            _ = PumpOutputAsync(session, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            Close();
        }
        catch (Exception)
        {
            Status.Text = "SSH terminal is unavailable. The vault remains open and unchanged.";
        }
    }

    private async Task InitializeWebViewAsync()
    {
        var tempRoot = Path.GetFullPath(Path.GetTempPath());
        webViewDataFolder = Path.Combine(tempRoot, "PasswordManager.WebView2." + Guid.NewGuid().ToString("N"));
        var options = new CoreWebView2EnvironmentOptions(
            additionalBrowserArguments: "--disable-features=msEdgeAutofill,msEdgePasswordManager,msSmartScreenProtection --no-proxy-server");
        var environment = await CoreWebView2Environment.CreateAsync(browserExecutableFolder: null, webViewDataFolder, options).ConfigureAwait(true);
        await WebView.EnsureCoreWebView2Async(environment).ConfigureAwait(true);

        var core = WebView.CoreWebView2;
        core.Settings.AreDefaultContextMenusEnabled = false;
        core.Settings.AreDevToolsEnabled = false;
        core.Settings.AreBrowserAcceleratorKeysEnabled = false;
        core.Settings.IsStatusBarEnabled = false;
        core.Settings.IsZoomControlEnabled = false;
        core.Settings.IsPasswordAutosaveEnabled = false;
        core.Settings.IsGeneralAutofillEnabled = false;
        core.Settings.AreHostObjectsAllowed = false;
        core.NavigationStarting += (_, args) =>
        {
            if (!string.Equals(args.Uri, TerminalUri.AbsoluteUri, StringComparison.Ordinal))
            {
                args.Cancel = true;
            }
        };
        core.NewWindowRequested += (_, args) => args.Handled = true;
        core.DownloadStarting += (_, args) => args.Cancel = true;
        core.WebMessageReceived += WebMessageReceived;

        var assetFolder = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Terminal", "dist"));
        if (!Directory.Exists(assetFolder))
        {
            throw new DirectoryNotFoundException("Embedded terminal assets are missing.");
        }

        core.SetVirtualHostNameToFolderMapping(
            "passwordmanager.local",
            assetFolder,
            CoreWebView2HostResourceAccessKind.DenyCors);
        core.Navigate(TerminalUri.AbsoluteUri);
    }

    private bool ConfirmFingerprint(string fingerprint)
    {
        return Dispatcher.Invoke(() => MessageBox.Show(
            $"First connection to {profile.Host}:{profile.Port}.\n\nHost key fingerprint:\n{fingerprint}\n\nTrust and save it inside this vault?",
            "SSH host key verification",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes);
    }

    private async void WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs eventArgs)
    {
        if (eventArgs.WebMessageAsJson.Length > 64 * 1024)
        {
            return;
        }

        try
        {
            using var json = JsonDocument.Parse(eventArgs.WebMessageAsJson, new JsonDocumentOptions { MaxDepth = 8 });
            var root = json.RootElement;
            if (!root.TryGetProperty("type", out var typeElement) || typeElement.GetString() is not { } type)
            {
                return;
            }

            if (type == "ready")
            {
                terminalReady = true;
                PostMessage(new { type = "focus" });
                return;
            }

            if (session is null)
            {
                return;
            }

            if (type == "input" && root.TryGetProperty("data", out var dataElement) && dataElement.GetString() is { Length: <= 32768 } data)
            {
                var bytes = Encoding.UTF8.GetBytes(data);
                try
                {
                    await session.InputOutput.WriteAsync(bytes, cancellation.Token).ConfigureAwait(true);
                    await session.InputOutput.FlushAsync(cancellation.Token).ConfigureAwait(true);
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
                }
            }
            else if (type == "resize" &&
                     root.TryGetProperty("cols", out var colsElement) && colsElement.TryGetUInt32(out var cols) &&
                     root.TryGetProperty("rows", out var rowsElement) && rowsElement.TryGetUInt32(out var rows))
            {
                session.Resize(cols, rows, cols * 9, rows * 18);
            }
        }
        catch (JsonException)
        {
            // Malformed WebView messages are untrusted and ignored.
        }
    }

    private async Task PumpOutputAsync(SshTerminalSession activeSession, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(
            activeSession.InputOutput,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 8192,
            leaveOpen: true);
        var buffer = new char[8192];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var filtered = osc52Filter.Filter(new string(buffer, 0, read));
                if (filtered.Length > 0 && terminalReady)
                {
                    await Dispatcher.InvokeAsync(() => PostMessage(new { type = "output", data = filtered }));
                }
            }
        }
        catch (Exception exception) when (exception is IOException or DecoderFallbackException or OperationCanceledException)
        {
            // Closing, network loss, or invalid UTF-8 terminates only this terminal session.
        }
    }

    private void PostMessage<T>(T message)
    {
        WebView.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(message));
    }

    private async void TerminalClosed(object? sender, EventArgs eventArgs)
    {
        cancellation.Cancel();
        if (session is not null)
        {
            await session.DisposeAsync().ConfigureAwait(true);
            session = null;
        }

        WebView.Dispose();
        cancellation.Dispose();
        DeleteWebViewDataFolder();
        disposed = true;
    }

    private void DeleteWebViewDataFolder()
    {
        if (string.IsNullOrEmpty(webViewDataFolder))
        {
            return;
        }

        var fullPath = Path.GetFullPath(webViewDataFolder);
        var tempRoot = Path.GetFullPath(Path.GetTempPath());
        if (!fullPath.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(fullPath).StartsWith("PasswordManager.WebView2.", StringComparison.Ordinal))
        {
            return;
        }

        try
        {
            Directory.Delete(fullPath, recursive: true);
        }
        catch (IOException)
        {
            // WebView may still hold a runtime file briefly; no vault plaintext was stored intentionally.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort cleanup only; the directory is unique and contains browser runtime state.
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        cancellation.Cancel();
        session?.Dispose();
        session = null;
        WebView.Dispose();
        cancellation.Dispose();
        DeleteWebViewDataFolder();
        GC.SuppressFinalize(this);
    }
}
