using System.Globalization;
using Ipa.Contracts;
using Ipa.Contracts.Reporting;
using Ipa.Reporting.Html;
using Microsoft.Playwright;

namespace Ipa.Reporting.Pdf;

/// <summary>Raised when the bundled browser cannot render the report.</summary>
public sealed class PdfRenderException : Exception
{
    public PdfRenderException(string message, Exception? inner = null) : base(message, inner)
    {
    }
}

/// <summary>Options controlling one render.</summary>
public sealed record PdfRenderOptions
{
    /// <summary>Confidentiality label repeated in the page footer.</summary>
    public string ConfidentialityLabel { get; init; } = "Confidential";

    /// <summary>Customer name repeated in the page header.</summary>
    public string? CustomerName { get; init; }

    /// <summary>Product name shown in the header, honouring any white-label override.</summary>
    public string ProductName { get; init; } = ProductInfo.Name;

    /// <summary>Paper format. A4 by default.</summary>
    public string Format { get; init; } = "A4";

    /// <summary>Render timeout in milliseconds.</summary>
    public float TimeoutMilliseconds { get; init; } = 120_000;

    /// <summary>
    /// Path of the browser executable to use. A packaged release points this at the browser it
    /// ships, so rendering never depends on a browser being installed on the operator's machine or
    /// on the exact build the library would otherwise look for. When unset, the environment
    /// variable named by <see cref="BrowserPathVariable"/> is consulted and the library's own
    /// resolution is used as the final fallback.
    /// </summary>
    public string? BrowserExecutablePath { get; init; }

    /// <summary>Environment variable naming the bundled browser executable.</summary>
    public const string BrowserPathVariable = "IPA_BROWSER_EXECUTABLE";

    /// <summary>Resolves the browser executable, returning null to use the library's own resolution.</summary>
    public string? ResolveBrowserPath()
    {
        if (!string.IsNullOrWhiteSpace(BrowserExecutablePath))
        {
            return BrowserExecutablePath;
        }

        var configured = Environment.GetEnvironmentVariable(BrowserPathVariable);

        return string.IsNullOrWhiteSpace(configured) ? null : configured;
    }
}

/// <summary>
/// Renders the composed HTML to PDF through the bundled headless browser.
/// </summary>
/// <remarks>
/// Rendering is entirely offline: the document embeds its styles, images and charts, and the page
/// is loaded from memory rather than from a network address. The browser is launched with no
/// network access of its own, so a hostile value inside a directory object cannot cause a request
/// to leave the operator's machine even if it were to escape escaping.
///
/// Version one does not encrypt the PDF. The caller warns the operator that an exported report
/// leaves the encrypted project boundary.
/// </remarks>
public sealed class PdfRenderer : IAsyncDisposable
{
    private IPlaywright? _playwright;
    private IBrowser? _browser;

    /// <summary>Warning shown before a report is exported.</summary>
    public const string ExportWarning =
        "Exported reports are not encrypted. A generated PDF leaves the encrypted project boundary " +
        "and must be handled according to its confidentiality label.";

    /// <summary>Renders HTML to a PDF file.</summary>
    public async Task RenderAsync(
        string html,
        string outputPath,
        PdfRenderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(html);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(options);

        var bytes = await RenderAsync(html, options, cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Renders HTML to PDF bytes.</summary>
    public async Task<byte[]> RenderAsync(
        string html,
        PdfRenderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(html);
        ArgumentNullException.ThrowIfNull(options);

        cancellationToken.ThrowIfCancellationRequested();

        var browser = await EnsureBrowserAsync(options).ConfigureAwait(false);

        await using var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            // The report is a fixed document: no service worker, no permission and no external
            // request is expected or required.
            JavaScriptEnabled = false,
            Offline = true,
        }).ConfigureAwait(false);

        // Any request that somehow escapes the document is refused rather than allowed out.
        await context.RouteAsync("**/*", route => route.AbortAsync()).ConfigureAwait(false);

        var page = await context.NewPageAsync().ConfigureAwait(false);

        try
        {
            await page.SetContentAsync(html, new PageSetContentOptions
            {
                WaitUntil = WaitUntilState.Load,
                Timeout = options.TimeoutMilliseconds,
            }).ConfigureAwait(false);

            // The print media type is used so that the page-break rules in the stylesheet apply,
            // which is what keeps pagination deterministic between runs and platforms.
            await page.EmulateMediaAsync(new PageEmulateMediaOptions { Media = Media.Print })
                .ConfigureAwait(false);

            return await page.PdfAsync(new PagePdfOptions
            {
                Format = options.Format,
                PrintBackground = true,
                DisplayHeaderFooter = true,
                HeaderTemplate = BuildHeaderTemplate(options),
                FooterTemplate = BuildFooterTemplate(options),
                Margin = new Margin
                {
                    Top = "22mm",
                    Bottom = "20mm",
                    Left = "14mm",
                    Right = "14mm",
                },
            }).ConfigureAwait(false);
        }
        catch (PlaywrightException ex)
        {
            throw new PdfRenderException(
                "The report could not be rendered by the bundled browser. " +
                "Confirm that the browser component shipped with this release is present.",
                ex);
        }
        finally
        {
            await page.CloseAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Header repeated on every page: product name and customer.</summary>
    public static string BuildHeaderTemplate(PdfRenderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return $"""
            <div style="width:100%;font-family:sans-serif;font-size:8pt;color:#5b5b5b;
                        padding:0 14mm;display:flex;justify-content:space-between;">
              <span>{HtmlText.Escape(options.ProductName)}</span>
              <span>{HtmlText.Escape(options.CustomerName ?? string.Empty)}</span>
            </div>
            """;
    }

    /// <summary>Footer repeated on every page: confidentiality label and page numbers.</summary>
    public static string BuildFooterTemplate(PdfRenderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return $"""
            <div style="width:100%;font-family:sans-serif;font-size:8pt;color:#5b5b5b;
                        padding:0 14mm;display:flex;justify-content:space-between;">
              <span>{HtmlText.Escape(options.ConfidentialityLabel)}</span>
              <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
            </div>
            """;
    }

    private async Task<IBrowser> EnsureBrowserAsync(PdfRenderOptions options)
    {
        if (_browser is not null)
        {
            return _browser;
        }

        try
        {
            _playwright = await Playwright.CreateAsync().ConfigureAwait(false);

            _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true,
                ExecutablePath = options.ResolveBrowserPath(),
                Args =
                [
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--no-first-run",
                    "--disable-default-apps",
                ],
            }).ConfigureAwait(false);

            return _browser;
        }
        catch (Exception ex)
        {
            throw new PdfRenderException(
                "The bundled browser could not be started. Report generation needs the browser " +
                "component that ships with this release. Set the " + PdfRenderOptions.BrowserPathVariable +
                " environment variable to point at a browser executable if it is installed elsewhere.",
                ex);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_browser is not null)
        {
            await _browser.CloseAsync().ConfigureAwait(false);
            _browser = null;
        }

        _playwright?.Dispose();
        _playwright = null;
    }
}

/// <summary>Composes and renders a report in one step.</summary>
public sealed class ReportGenerator
{
    private readonly HtmlReportComposer _composer = new();

    /// <summary>Composes the HTML for a report model.</summary>
    public string ComposeHtml(Model.ReportModel model) => _composer.Compose(model);

    /// <summary>Composes and renders a report to a PDF file.</summary>
    public async Task GenerateAsync(
        Model.ReportModel model,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(model);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

        var html = ComposeHtml(model);

        await using var renderer = new PdfRenderer();

        await renderer.RenderAsync(
                html,
                outputPath,
                new PdfRenderOptions
                {
                    ConfidentialityLabel = model.Profile.Branding.ConfidentialityLabel,
                    CustomerName = model.Profile.Branding.CustomerName ?? model.Metadata.CustomerName,
                    ProductName = model.Profile.Branding.EffectiveProductName,
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// The warnings an operator must see before a report is exported. The first is always shown; the
    /// privacy warning appears only when the profile would place sensitive material into the export.
    /// </summary>
    public static IReadOnlyList<string> ExportWarnings(ReportProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var warnings = new List<string> { PdfRenderer.ExportWarning };

        if (profile.IncludeRawObjectAttributes)
        {
            warnings.Add(
                "Raw object attributes are included. The exported report will contain directory and " +
                "tenant attribute values in clear text.");
        }

        if (profile.IncludeFullAffectedObjectLists)
        {
            warnings.Add(
                "Full affected-object lists are included. The exported report will name every affected " +
                "account, computer, group and policy rather than a sample.");
        }

        if (profile.IncludeAttachments)
        {
            warnings.Add(
                "Operator attachments are included in the evidence appendix and will leave the " +
                "encrypted project boundary with the report.");
        }

        return warnings;
    }

    /// <summary>Suggests a file name for the exported report.</summary>
    public static string SuggestFileName(string customerName, DateTimeOffset generatedAt)
    {
        var safeCustomer = new string(customerName
            .Where(character => char.IsLetterOrDigit(character) || character is ' ' or '-' or '_')
            .ToArray())
            .Trim()
            .Replace(' ', '-');

        if (safeCustomer.Length == 0)
        {
            safeCustomer = "assessment";
        }

        return $"{ProductInfo.ShortName}-{safeCustomer}-" +
               $"{generatedAt.ToString("yyyyMMdd", CultureInfo.InvariantCulture)}.pdf";
    }
}
