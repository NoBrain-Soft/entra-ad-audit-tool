using CommunityToolkit.Mvvm.ComponentModel;

namespace Ipa.Desktop.ViewModels;

/// <summary>Base class for every view model in the application.</summary>
public abstract partial class ViewModelBase : ObservableObject
{
    /// <summary>Title shown in the workflow header.</summary>
    public abstract string Title { get; }

    /// <summary>One-line description shown under the title.</summary>
    public virtual string Description => string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _statusMessage;

    [ObservableProperty]
    private string? _errorMessage;

    /// <summary>Clears the status and error messages before a new operation.</summary>
    protected void ClearMessages()
    {
        StatusMessage = null;
        ErrorMessage = null;
    }

    /// <summary>
    /// Reports a failure to the operator. The message is scrubbed first, because an exception
    /// message can carry a connection string or a credential fragment.
    /// </summary>
    protected void ReportFailure(string context, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        ErrorMessage = $"{context}: {Contracts.Security.Redaction.Scrub(exception.Message)}";
    }
}
