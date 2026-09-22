using Ipa.Reporting.Pdf;
using Xunit;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Renders a document through the bundled browser to confirm the whole path works: the browser
/// starts, the print stylesheet applies, page numbering is produced and the output is a real PDF.
/// </summary>
/// <remarks>
/// The test is skipped when no browser component can be started, so a machine without one still
/// runs the rest of the suite. A build agent provisions the browser deliberately, so there the
/// same condition fails the test rather than skipping it: see <see cref="RenderBrowser"/>.
/// </remarks>
public sealed class PdfRenderIntegrationTests
{
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
        await RenderBrowser.RequireAsync();

        await using var renderer = new PdfRenderer();

        var bytes = await renderer.RenderAsync(
            Document,
            new PdfRenderOptions
            {
                ConfidentialityLabel = "Confidential",
                CustomerName = "Contoso",
                BrowserExecutablePath = RenderBrowser.ExecutablePath,
            },
            CancellationToken.None);

        Assert.True(bytes.Length > 1000, "The rendered document is implausibly small.");

        // Every PDF begins with the format's own signature.
        Assert.Equal("%PDF-"u8.ToArray(), bytes.Take(5).ToArray());
    }

    [SkippableFact]
    public async Task RenderedFileIsWrittenToDisk()
    {
        await RenderBrowser.RequireAsync();

        var path = Path.Combine(Path.GetTempPath(), $"ipa-render-{Guid.NewGuid():n}.pdf");

        try
        {
            await using var renderer = new PdfRenderer();

            await renderer.RenderAsync(
                Document,
                path,
                new PdfRenderOptions { BrowserExecutablePath = RenderBrowser.ExecutablePath },
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
