namespace ChromePolicyManager.Admin.Services;

public enum ToastLevel
{
    Success,
    Error,
    Warning,
    Info
}

public sealed class ToastMessage
{
    public Guid Id { get; } = Guid.NewGuid();
    public string Text { get; init; } = "";
    public ToastLevel Level { get; init; } = ToastLevel.Info;
}

/// <summary>
/// Lightweight notification service (Bootstrap toasts). Replaces MudBlazor's ISnackbar.
/// Components inject this to raise toasts; <see cref="Components.Shared.ToastHost"/> renders them.
/// </summary>
public sealed class ToastService
{
    public event Action? OnChange;

    private readonly List<ToastMessage> _messages = new();
    public IReadOnlyList<ToastMessage> Messages => _messages;

    public void Show(string text, ToastLevel level = ToastLevel.Info)
    {
        _messages.Add(new ToastMessage { Text = text, Level = level });
        OnChange?.Invoke();
    }

    public void Success(string text) => Show(text, ToastLevel.Success);
    public void Error(string text) => Show(text, ToastLevel.Error);
    public void Warning(string text) => Show(text, ToastLevel.Warning);
    public void Info(string text) => Show(text, ToastLevel.Info);

    public void Remove(Guid id)
    {
        var item = _messages.FirstOrDefault(m => m.Id == id);
        if (item is not null)
        {
            _messages.Remove(item);
            OnChange?.Invoke();
        }
    }
}
