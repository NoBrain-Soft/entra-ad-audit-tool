using Ipa.Reporting.Html;
using Ipa.Reporting.Pdf;
using Xunit;

namespace Ipa.Reporting.Tests;

/// <summary>
/// Writes a full sample report when a destination is supplied, so a release can be checked visually
/// on both platforms with small and very large data sets. Skipped in an ordinary test run.
/// </summary>
public sealed class SampleReportTests
{
    /// <summary>Environment variable naming the directory a sample report is written to.</summary>
    public const string OutputVariable = "IPA_SAMPLE_REPORT_DIR";

    [SkippableFact]
    public async Task SampleReportIsWrittenWhenRequested()
    {
        var directory = Environment.GetEnvironmentVariable(OutputVariable);

        // Writing the sample is opt-in, so its absence is a genuine reason to skip. A missing
        // browser is not, once the sample has been asked for.
        Skip.If(string.IsNullOrWhiteSpace(directory), "No sample report directory was requested.");

        await RenderBrowser.RequireAsync();

        Directory.CreateDirectory(directory!);

        var model = SampleReportData.Build();
        var html = new HtmlReportComposer().Compose(model);

        await File.WriteAllTextAsync(
            Path.Combine(directory!, "sample-report.html"),
            html,
            CancellationToken.None);

        await using var renderer = new PdfRenderer();

        await renderer.RenderAsync(
            html,
            Path.Combine(directory!, "sample-report.pdf"),
            new PdfRenderOptions
            {
                ConfidentialityLabel = model.Profile.Branding.ConfidentialityLabel,
                CustomerName = model.Metadata.CustomerName,
                BrowserExecutablePath = RenderBrowser.ExecutablePath,
            },
            CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(directory!, "sample-report.pdf")));
    }
}
