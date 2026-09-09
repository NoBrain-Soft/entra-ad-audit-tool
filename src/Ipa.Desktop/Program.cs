using Avalonia;
using Ipa.Contracts;
using Ipa.Desktop.Services;

namespace Ipa.Desktop;

/// <summary>Application entry point.</summary>
internal static class Program
{
    /// <summary>
    /// Starts the desktop application. Initialisation happens before any Avalonia type is touched,
    /// which is what the framework requires.
    /// </summary>
    [STAThread]
    public static int Main(string[] args)
    {
        try
        {
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            // A failure this early has no window to report into, so the message goes to the
            // console. It is scrubbed first: an early failure can carry a connection string.
            Console.Error.WriteLine(
                $"{ProductInfo.Name} could not start: " +
                Contracts.Security.Redaction.Scrub(ex.Message));

            return 1;
        }
    }

    /// <summary>Builds the application. Referenced by the designer as well as by <see cref="Main"/>.</summary>
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
