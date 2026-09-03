using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;

namespace PasswordManager.App.Services;

public sealed class AutoLockService : IDisposable
{
    private readonly DispatcherTimer timer;
    private DateTimeOffset lastActivity = DateTimeOffset.UtcNow;
    private bool disposed;

    public AutoLockService()
    {
        timer = new DispatcherTimer(TimeSpan.FromSeconds(10), DispatcherPriority.Background, CheckIdle, Application.Current.Dispatcher);
        SystemEvents.SessionSwitch += SessionSwitch;
        SystemEvents.PowerModeChanged += PowerModeChanged;
    }

    public event EventHandler? LockRequested;

    public int TimeoutMinutes { get; set; } = 15;

    public void NotifyActivity() => lastActivity = DateTimeOffset.UtcNow;

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        timer.Stop();
        SystemEvents.SessionSwitch -= SessionSwitch;
        SystemEvents.PowerModeChanged -= PowerModeChanged;
    }

    private void CheckIdle(object? sender, EventArgs eventArgs)
    {
        if (DateTimeOffset.UtcNow - lastActivity >= TimeSpan.FromMinutes(Math.Clamp(TimeoutMinutes, 1, 120)))
        {
            lastActivity = DateTimeOffset.UtcNow;
            LockRequested?.Invoke(this, EventArgs.Empty);
        }
    }

    private void SessionSwitch(object sender, SessionSwitchEventArgs eventArgs)
    {
        if (eventArgs.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
        {
            Application.Current.Dispatcher.BeginInvoke(() => LockRequested?.Invoke(this, EventArgs.Empty));
        }
    }

    private void PowerModeChanged(object sender, PowerModeChangedEventArgs eventArgs)
    {
        if (eventArgs.Mode == PowerModes.Suspend)
        {
            Application.Current.Dispatcher.BeginInvoke(() => LockRequested?.Invoke(this, EventArgs.Empty));
        }
    }
}

