using System.Windows;
using PasswordManager.App.Infrastructure;
using PasswordManager.App.Views;

namespace PasswordManager.App;

public partial class App : Application, IDisposable
{
    private SingleInstanceCoordinator? coordinator;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var arguments = CommandLineOptions.Parse(e.Args);
        Localizer.Instance.SetLanguage(arguments.Language);

        coordinator = new SingleInstanceCoordinator();
        if (!coordinator.TryBecomePrimary(arguments.VaultPaths))
        {
            Shutdown();
            return;
        }

        var mainWindow = new MainWindow(arguments.VaultPaths);
        coordinator.PathsReceived += (_, paths) => mainWindow.Dispatcher.Invoke(() => mainWindow.OpenPaths(paths));
        mainWindow.Closed += (_, _) =>
        {
            coordinator.Dispose();
            coordinator = null;
            Shutdown();
        };

        MainWindow = mainWindow;
        mainWindow.Show();
    }

    public void Dispose()
    {
        coordinator?.Dispose();
        coordinator = null;
        GC.SuppressFinalize(this);
    }
}
