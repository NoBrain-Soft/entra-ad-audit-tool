using Ipa.Contracts.Reporting;

namespace Ipa.Reporting.Html;

/// <summary>
/// The report stylesheet. It is generated rather than loaded so that the operator's accent colours
/// are validated before they reach a declaration, and so that generation stays entirely offline.
/// </summary>
public static class ReportStyles
{
    /// <summary>Builds the stylesheet for a branding profile.</summary>
    public static string Build(BrandingProfile branding)
    {
        ArgumentNullException.ThrowIfNull(branding);

        var primary = HtmlText.CssColor(branding.PrimaryColor, "#1f3a5f");
        var secondary = HtmlText.CssColor(branding.SecondaryColor, "#4b7bb5");

        return $$"""
            :root {
              --primary: {{primary}};
              --secondary: {{secondary}};
              --critical: #a4243b;
              --high: #cf5c36;
              --medium: #c9a227;
              --low: #5a7d7c;
              --pass: #2f6b4f;
              --ink: #1c1c1c;
              --muted: #5b5b5b;
              --rule: #d6d6d6;
              --panel: #f6f7f9;
            }

            @page {
              size: A4;
              margin: 20mm 16mm 22mm 16mm;
            }

            html { font-size: 10.5pt; }

            body {
              font-family: "Segoe UI", "Noto Sans", "DejaVu Sans", system-ui, sans-serif;
              color: var(--ink);
              line-height: 1.45;
              margin: 0;
            }

            h1, h2, h3, h4 { color: var(--primary); font-weight: 600; margin: 0 0 0.4em; }
            h1 { font-size: 2.1rem; }
            h2 { font-size: 1.45rem; border-bottom: 2px solid var(--secondary); padding-bottom: 0.25em; }
            h3 { font-size: 1.15rem; }
            h4 { font-size: 1rem; }

            p { margin: 0 0 0.7em; }

            /* Each numbered section starts on a new page, and headings never end one. */
            section.report-section { page-break-before: always; break-before: page; }
            section.report-section:first-of-type { page-break-before: auto; break-before: auto; }
            h2, h3, h4 { page-break-after: avoid; break-after: avoid; }
            table, figure, .finding { page-break-inside: avoid; break-inside: avoid; }

            table { border-collapse: collapse; width: 100%; margin: 0 0 1em; font-size: 0.92rem; }
            th, td { border: 1px solid var(--rule); padding: 5px 8px; text-align: left; vertical-align: top; }
            th { background: var(--panel); font-weight: 600; }

            /* Wide tables repeat their header on every page they span. */
            thead { display: table-header-group; }
            tfoot { display: table-footer-group; }

            .cover { text-align: left; padding-top: 28mm; page-break-after: always; }
            .cover-logo { max-height: 26mm; margin-bottom: 12mm; }
            .cover-product { color: var(--secondary); font-size: 1.1rem; letter-spacing: 0.08em; text-transform: uppercase; }
            .cover-customer { font-size: 2.6rem; color: var(--primary); margin: 0.2em 0; }
            .cover-meta {
              margin-top: 14mm; font-size: 1rem;
              display: grid; grid-template-columns: 48mm 1fr; row-gap: 0.45em; column-gap: 4mm;
            }
            .cover-meta dt { font-weight: 600; color: var(--muted); margin: 0; }
            .cover-meta dd { margin: 0; }
            .confidentiality { margin-top: 18mm; font-weight: 600; color: var(--critical); letter-spacing: 0.06em; }

            .toc ol { list-style: none; padding-left: 0; }
            .toc li { padding: 0.2em 0; border-bottom: 1px dotted var(--rule); }

            .score-grid {
              display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
              gap: 10px; margin-bottom: 1em;
            }
            .score-card {
              border: 1px solid var(--rule); border-top-width: 5px;
              border-radius: 4px; padding: 10px 12px; background: #fff;
            }
            .score-label { font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0; }
            .score-value { font-size: 2.1rem; font-weight: 700; color: var(--primary); margin: 0.1em 0; }
            .score-scale { font-size: 0.9rem; font-weight: 400; color: var(--muted); }
            .score-coverage { font-size: 0.85rem; color: var(--muted); margin: 0; }
            .score-provisional { font-size: 0.78rem; color: var(--high); margin: 0.3em 0 0; font-weight: 600; }

            .chart { margin: 0 0 1.2em; }
            .chart-label { font-size: 12px; fill: var(--ink); }
            .chart-value { font-size: 12px; fill: var(--muted); }
            .chart-caption { font-size: 0.86rem; color: var(--muted); margin-top: 0.3em; }
            .chart-empty { color: var(--muted); font-style: italic; }
            .chart-data { margin-top: 0.4em; }

            .finding { border-left: 4px solid var(--rule); padding: 0.5em 0 0.5em 0.9em; margin-bottom: 1.1em; }
            .finding.critical { border-left-color: var(--critical); }
            .finding.high { border-left-color: var(--high); }
            .finding.medium { border-left-color: var(--medium); }
            .finding.low { border-left-color: var(--low); }
            .finding-heading { display: flex; justify-content: space-between; gap: 1em; align-items: baseline; }
            .finding-id { font-family: "Cascadia Mono", "DejaVu Sans Mono", monospace; font-size: 0.85rem; color: var(--muted); }

            .badge {
              display: inline-block; padding: 1px 7px; border-radius: 9px; font-size: 0.74rem;
              font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: #fff;
            }
            .badge.critical { background: var(--critical); }
            .badge.high { background: var(--high); }
            .badge.medium { background: var(--medium); color: #2b2b2b; }
            .badge.low { background: var(--low); }
            .badge.informational { background: var(--muted); }
            .badge.pass { background: var(--pass); }
            .badge.annotated { background: var(--secondary); }

            .callout {
              border: 1px solid var(--secondary); background: var(--panel);
              border-radius: 4px; padding: 0.7em 0.9em; margin: 0 0 1em;
            }
            .callout.warning { border-color: var(--high); }
            .callout strong { color: var(--primary); }

            .muted { color: var(--muted); }
            .small { font-size: 0.85rem; }
            .mono { font-family: "Cascadia Mono", "DejaVu Sans Mono", monospace; font-size: 0.85rem; word-break: break-all; }

            .visually-hidden {
              position: absolute; width: 1px; height: 1px; overflow: hidden;
              clip: rect(0 0 0 0); white-space: nowrap;
            }
            """;
    }
}
