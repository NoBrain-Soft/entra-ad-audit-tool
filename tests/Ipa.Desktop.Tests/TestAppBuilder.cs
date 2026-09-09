using Avalonia;
using Avalonia.Headless;
using Ipa.Desktop;

namespace Ipa.Desktop.Tests;

/// <summary>
/// Runs interface tests on a headless Avalonia session, so views are really constructed, bound and
/// laid out on a dispatcher thread rather than merely instantiated.
/// </summary>
public static class HeadlessUi
{
    private static readonly Lazy<HeadlessUnitTestSession> Session = new(() =>
        HeadlessUnitTestSession.StartNew(typeof(App)));

    /// <summary>Runs an action on the interface thread and waits for it to finish.</summary>
    public static void Run(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);

        Session.Value.Dispatch(
            () =>
            {
                action();
                return Task.CompletedTask;
            },
            CancellationToken.None)
            .GetAwaiter()
            .GetResult();
    }

    /// <summary>Builds the headless application. Referenced by the session factory.</summary>
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions());
}
