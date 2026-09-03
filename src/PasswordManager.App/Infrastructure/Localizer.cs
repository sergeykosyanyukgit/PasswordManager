using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace PasswordManager.App.Infrastructure;

public sealed class Localizer : INotifyPropertyChanged
{
    private static readonly Dictionary<string, (string En, string Ru)> Strings =
        new Dictionary<string, (string En, string Ru)>(StringComparer.Ordinal)
        {
            ["AppTitle"] = ("PasswordManager", "PasswordManager"),
            ["Open"] = ("Open", "Открыть"),
            ["Create"] = ("Create", "Создать"),
            ["SaveAs"] = ("Save As", "Сохранить как"),
            ["ChangeMasterPassword"] = ("Change master password", "Сменить мастер-пароль"),
            ["LockAll"] = ("Lock all", "Заблокировать все"),
            ["Language"] = ("Language", "Язык"),
            ["AddFolder"] = ("New folder", "Новая папка"),
            ["AddRecord"] = ("New record", "Новая запись"),
            ["Delete"] = ("Delete", "Удалить"),
            ["RecycleBin"] = ("Recycle bin", "Корзина"),
            ["Search"] = ("Search this vault", "Поиск в сейфе"),
            ["Name"] = ("Name", "Имя"),
            ["Type"] = ("Type", "Тип"),
            ["UserName"] = ("User name", "Логин"),
            ["Email"] = ("Email", "Почта"),
            ["Password"] = ("Password", "Пароль"),
            ["Url"] = ("URL", "URL"),
            ["Notes"] = ("Notes", "Заметка"),
            ["Save"] = ("Save", "Сохранить"),
            ["Cancel"] = ("Cancel", "Отмена"),
            ["Generate"] = ("Generate", "Сгенерировать"),
            ["CheckPassword"] = ("Check with HIBP", "Проверить в HIBP"),
            ["Compromised"] = ("COMPROMISED PASSWORD", "ПАРОЛЬ СКОМПРОМЕТИРОВАН"),
            ["Copy"] = ("Copy", "Копировать"),
            ["ConnectSsh"] = ("Open SSH terminal", "Открыть SSH-терминал"),
            ["MasterPassword"] = ("Master password", "Мастер-пароль"),
            ["ConfirmPassword"] = ("Confirm password", "Подтвердите пароль"),
            ["Unlock"] = ("Unlock", "Разблокировать"),
            ["SecurityError"] = ("Security control failed", "Ошибка защитного механизма"),
            ["NoVault"] = ("Open or create a vault. No recent-file list is stored.", "Откройте или создайте сейф. Список недавних файлов не сохраняется."),
        };

    private bool isRussian;

    public static Localizer Instance { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    public string this[string key] => Strings.TryGetValue(key, out var value)
        ? (isRussian ? value.Ru : value.En)
        : key;

    public string Language => isRussian ? "ru" : "en";

    public void SetLanguage(string? language)
    {
        var newValue = string.Equals(
            language ?? CultureInfo.CurrentUICulture.TwoLetterISOLanguageName,
            "ru",
            StringComparison.OrdinalIgnoreCase);
        if (newValue == isRussian)
        {
            return;
        }

        isRussian = newValue;
        OnPropertyChanged("Item[]");
        OnPropertyChanged(nameof(Language));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
