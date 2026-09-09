using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Ipa.Desktop.Services;
using Ipa.Desktop.ViewModels;
using Ipa.Desktop.Views;

namespace Ipa.Desktop;

/// <summary>The Avalonia application.</summary>
public partial class App : Application
{
    /// <inheritdoc />
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    /// <inheritdoc />
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var workspace = new AssessmentWorkspace();
            var viewModel = new MainWindowViewModel(workspace);

            var window = new MainWindow { DataContext = viewModel };

            // The ephemeral session is deleted on a normal exit. A crash leaves it behind, which
            // the welcome screen detects and offers to clean up on the next start.
            desktop.ShutdownRequested += (_, _) => workspace.Dispose();

            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
