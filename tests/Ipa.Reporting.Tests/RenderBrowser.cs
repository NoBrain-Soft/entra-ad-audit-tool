using Ipa.Reporting.Pdf;
using Microsoft.Playwright;
using Xunit;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Decides whether the rendering tests can run, and which browser they render with.
/// </summary>
/// <remarks>
/// A developer machine without a browser component skips the rendering tests, so the rest of the
/// suite still runs there. A build agent is a different case: it provisions the browser on purpose,
/// so a missing one is a broken pipeline rather than an absent optional component. Skipping there
/// would let a build report success with no rendering coverage at all, which is the one outcome
/// these tests exist to prevent, so on an agent a missing browser fails instead.
/// </remarks>
internal static class RenderBrowser
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static Exception? _failure;
    private static bool _probed;

    /// <summary>
    /// The browser executable to render with, or null to let the library resolve its own.
    /// </summary>
    /// <remarks>
    /// Null does not mean that no browser is present. An agent that installed the browser in the
    /// place the library looks needs no path at all, which is why the presence of a path is not
    /// usable as the availability test.
    /// </remarks>
    public static string? ExecutablePath { get; } = ResolveExecutablePath();

    /// <summary>
    /// True where the environment is expected to provide a browser, so its absence is a failure.
    /// </summary>
    public static bool IsRequired { get; } =
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CI"));

    /// <summary>
    /// Confirms that a browser can actually be started, skipping the calling test where rendering
    /// is optional and failing it where rendering is required.
    /// </summary>
    public static async Task RequireAsync()
    {
        var failure = await ProbeOnceAsync().ConfigureAwait(false);

        if (failure is null)
        {
            return;
        }

        if (IsRequired)
        {
            throw new InvalidOperationException(
                "No usable browser component was found, so report rendering was not exercised. " +
                "This environment provisions the browser deliberately, so its absence is a " +
                "pipeline failure rather than a reason to skip the test. Check the step that " +
                "installs the browser, and set " + PdfRenderOptions.BrowserPathVariable +
                " if the browser lives somewhere the library does not look.",
                failure);
        }

        Skip.If(true, "No browser component is available on this machine: " + failure.Message);
    }

    /// <summary>Probes once per test run, because starting a browser is not free.</summary>
    private static async Task<Exception?> ProbeOnceAsync()
    {
        await Gate.WaitAsync().ConfigureAwait(false);

        try
        {
            if (!_probed)
            {
                _failure = await ProbeAsync().ConfigureAwait(false);
                _probed = true;
            }

            return _failure;
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>
    /// Starts and stops a browser. Only a start failure is an availability problem; anything that
    /// goes wrong after this point is a genuine test failure and is left to surface as one.
    /// </summary>
    private static async Task<Exception?> ProbeAsync()
    {
        try
        {
            using var playwright = await Playwright.CreateAsync().ConfigureAwait(false);

            var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true,
                ExecutablePath = ExecutablePath,
            }).ConfigureAwait(false);

            await browser.CloseAsync().ConfigureAwait(false);

            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    /// <summary>
    /// Resolves an explicit browser path: the release override first, then the directory a
    /// container that carries its own browser names, which holds a build the library would not
    /// otherwise look for.
    /// </summary>
    private static string? ResolveExecutablePath()
    {
        var configured = Environment.GetEnvironmentVariable(PdfRenderOptions.BrowserPathVariable);

        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var root = Environment.GetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH");

        if (string.IsNullOrWhiteSpace(root))
        {
            return null;
        }

        var candidate = Path.Combine(root, "chromium");

        return File.Exists(candidate) ? candidate : null;
    }
}
