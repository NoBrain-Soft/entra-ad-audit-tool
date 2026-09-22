using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Ipa.Contracts.Assessment;
using Ipa.Contracts.Collection;
using Ipa.Core.Collection;
using Ipa.Core.Tests.Fixtures;
using Ipa.Desktop;
using Ipa.Desktop.Services;
using Ipa.Desktop.ViewModels;
using Ipa.Desktop.Views;

namespace Ipa.UiCapture;

/// <summary>
/// Renders every screen of the desktop application to PNG.
/// </summary>
/// <remarks>
/// Avalonia's headless platform is used with the real drawing backend rather than its stub, so
/// what is written out is what the renderer actually produces: bindings resolved, templates
/// applied, text laid out. No display server is involved, so the screens can be looked at on a
/// build agent and on either platform, which is what the equivalence criterion asks for.
///
/// This exists because an interface can pass every test it has and still be unusable. The first
/// run of this tool found three such defects, among them a welcome screen whose only button did
/// nothing.
/// </remarks>
internal static class Capture
{
    private const int WindowWidth = 1500;
    private const int WindowHeight = 950;

    private static string _outputDirectory = "artifacts/ui";

    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        _outputDirectory = args.Length > 0 ? args[0] : _outputDirectory;
        Directory.CreateDirectory(_outputDirectory);

        AppBuilder.Configure<App>()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .UseSkia()
            .WithInterFont()
            .SetupWithoutStarting();

        using var workspace = new AssessmentWorkspace();
        var shell = new MainWindowViewModel(workspace);

        var window = new MainWindow
        {
            DataContext = shell,
            Width = WindowWidth,
            Height = WindowHeight,
        };

        window.Show();

        Shoot(window, "01-welcome");

        // Driven through the interface, not around it, so a dead command shows up here.
        shell.Welcome.StartNewAssessmentCommand.Execute(null);
        FillDetails(shell);
        Shoot(window, "02-details");

        shell.Details.ContinueCommand.Execute(null);
        FillConnections(shell);
        Shoot(window, "03-connections");

        shell.GoTo(WorkflowStep.Preflight);
        Shoot(window, "04-preflight");

        shell.GoTo(WorkflowStep.Scope);
        Shoot(window, "05-scope");

        shell.Scope.ContinueCommand.Execute(null);
        Shoot(window, "06-collection");

        await workspace.CollectAsync(
            [new CollectionStage("Synthetic", [new SyntheticCollector()])],
            progress: null,
            CancellationToken.None);

        workspace.Evaluate();
        shell.UpdateStepAvailability();

        shell.GoTo(WorkflowStep.Findings);
        Shoot(window, "07-findings");

        shell.GoTo(WorkflowStep.Compliance);
        Shoot(window, "08-compliance");

        shell.GoTo(WorkflowStep.Report);
        Shoot(window, "09-report");

        Console.WriteLine($"Wrote the screens to {Path.GetFullPath(_outputDirectory)}.");

        return 0;
    }

    /// <summary>Lets the dispatcher settle, renders a frame and writes it out.</summary>
    private static void Shoot(Window window, string name)
    {
        // Bindings, layout and the step's own entry work all run as dispatcher jobs, and a job can
        // queue another, so the queue is drained rather than pumped once.
        for (var pass = 0; pass < 4; pass++)
        {
            Dispatcher.UIThread.RunJobs();
        }

        var frame = window.CaptureRenderedFrame();

        if (frame is null)
        {
            Console.Error.WriteLine($"{name}: nothing was rendered.");
            return;
        }

        var path = Path.Combine(_outputDirectory, name + ".png");

        using (frame)
        {
            frame.Save(path, new PngBitmapEncoderOptions());
        }

        Console.WriteLine($"{name}: {new FileInfo(path).Length / 1024} KiB");
    }

    /// <summary>Fills the details step with the fabricated engagement the screens describe.</summary>
    private static void FillDetails(MainWindowViewModel shell)
    {
        shell.Details.CustomerName = "Contoso Pharmaceuticals GmbH";
        shell.Details.CustomerReference = "CPG-2026-014";
        shell.Details.AssessorName = "A. Assessor";
        shell.Details.EngagementReference = "Identity posture review, Q1 2026";
        shell.Details.ScopeNotes =
            "Production forest corp.example and the matching Entra tenant. Read-only assessment " +
            "agreed with the customer's identity team for the window 01-05 March.";
    }

    /// <summary>
    /// Fills the connection step. Every value is fabricated, and no password is set: the screens
    /// must never carry a credential, not even a made-up one.
    /// </summary>
    private static void FillConnections(MainWindowViewModel shell)
    {
        shell.Connections.DirectoryServer = "dc01.corp.example";
        shell.Connections.DirectoryDomain = "CORP";
        shell.Connections.DirectoryUserName = "svc-assessment";
        shell.Connections.TenantId = "8f4c2b17-0d3a-4e55-9a61-7c2e5b40d9aa";
        shell.Connections.ClientId = "2a6d91c4-55b8-4f0e-8c73-1e9a4d6b2f30";
    }
}
