namespace ChromePolicyManager.Admin.Services;

public sealed class ConfirmRequest
{
    public string Title { get; init; } = "Confirm";
    public string Message { get; init; } = "";
    public string ConfirmText { get; init; } = "OK";
    public string CancelText { get; init; } = "Cancel";
    public bool Danger { get; init; }
    public TaskCompletionSource<bool> Completion { get; } = new();
}

/// <summary>
/// Confirmation dialog service (Bootstrap modal). Replaces MudBlazor's DialogService.ShowMessageBox.
/// <see cref="Components.Shared.ConfirmDialog"/> subscribes and resolves the returned task.
/// </summary>
public sealed class ConfirmService
{
    public event Func<ConfirmRequest, Task>? OnConfirm;

    public Task<bool> ConfirmAsync(string title, string message,
        string confirmText = "OK", string cancelText = "Cancel", bool danger = false)
    {
        var request = new ConfirmRequest
        {
            Title = title,
            Message = message,
            ConfirmText = confirmText,
            CancelText = cancelText,
            Danger = danger
        };

        if (OnConfirm is null)
        {
            request.Completion.SetResult(false);
        }
        else
        {
            _ = OnConfirm.Invoke(request);
        }

        return request.Completion.Task;
    }
}
