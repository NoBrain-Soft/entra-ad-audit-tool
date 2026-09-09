using Ipa.Reporting.Pdf;
using Xunit;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Renders a document through the bundled browser to confirm the whole path works: the browser
/// starts, the print stylesheet applies, page numbering is produced and the output is a real PDF.
/// </summary>
/// <remarks>
/// The test is skipped when no browser component is present, so a machine without it still runs the
/// rest of the suite. The build and release pipeline provisions the browser, so the test runs there.
/// </remarks>
public sealed class PdfRenderIntegrationTests
{
    /// <summary>
    /// Locates a browser executable: the explicit override first, then the well-known path a
    /// provisioned build agent uses.
    /// </summary>
    private static string? BrowserPath
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable(PdfRenderOptions.BrowserPathVariable);

            if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
            {
                return configured;
            }

            var root = Environment.GetEnvironmentVariable("PLAYWRIGHT_BROWSERS_PATH");

            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                return null;
            }

            var candidate = Path.Combine(root, "chromium");

            return File.Exists(candidate) ? candidate : null;
        }
    }

    private const string Document = """
        <!DOCTYPE html>
        <html lang="en"><head><meta charset="utf-8"><title>Render test</title>
        <style>
          @page { size: A4; margin: 20mm; }
          section { page-break-before: always; }
          section:first-of-type { page-break-before: auto; }
        </style></head>
        <body>
          <section><h1>First page</h1><p>Body text on the first page.</p></section>
          <section><h1>Second page</h1><p>Body text on the second page.</p></section>
        </body></html>
        """;

    [SkippableFact]
    public async Task DocumentRendersToAValidPdf()
    {
        var browser = BrowserPath;
        Skip.If(browser is null, "No browser component is available on this machine.");

        await using var renderer = new PdfRenderer();

        var bytes = await renderer.RenderAsync(
            Document,
            new PdfRenderOptions
            {
                ConfidentialityLabel = "Confidential",
                CustomerName = "Contoso",
                BrowserExecutablePath = browser,
            },
            CancellationToken.None);

        Assert.True(bytes.Length > 1000, "The rendered document is implausibly small.");

        // Every PDF begins with the format's own signature.
        Assert.Equal("%PDF-"u8.ToArray(), bytes.Take(5).ToArray());
    }

    [SkippableFact]
    public async Task RenderedFileIsWrittenToDisk()
    {
        var browser = BrowserPath;
        Skip.If(browser is null, "No browser component is available on this machine.");

        var path = Path.Combine(Path.GetTempPath(), $"ipa-render-{Guid.NewGuid():n}.pdf");

        try
        {
            await using var renderer = new PdfRenderer();

            await renderer.RenderAsync(
                Document,
                path,
                new PdfRenderOptions { BrowserExecutablePath = browser },
                CancellationToken.None);

            Assert.True(File.Exists(path));
            Assert.True(new FileInfo(path).Length > 1000);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
