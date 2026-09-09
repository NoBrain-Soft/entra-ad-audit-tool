using System.Globalization;
using System.Text;

namespace Ipa.Reporting.Html;

/// <summary>One slice or bar of a chart.</summary>
/// <param name="Label">Category label.</param>
/// <param name="Value">Numeric value.</param>
/// <param name="Colour">CSS hexadecimal colour.</param>
public sealed record ChartDatum(string Label, double Value, string Colour);

/// <summary>
/// Renders charts as inline scalable vector graphics with a text equivalent.
/// </summary>
/// <remarks>
/// Every chart is accompanied by a data table carrying the same numbers, and every graphic declares
/// a title and description, so the report remains usable when the graphic cannot be seen or the
/// document is read by assistive technology. Nothing is fetched at render time: the graphics are
/// generated inline, which is also what keeps generation fully offline.
/// </remarks>
public static class AccessibleCharts
{
    /// <summary>Renders a horizontal bar chart with its text equivalent.</summary>
    public static string BarChart(string title, string description, IReadOnlyList<ChartDatum> data, string idPrefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentNullException.ThrowIfNull(data);

        if (data.Count == 0)
        {
            return $"<p class=\"chart-empty\">{HtmlText.Escape(title)}: no data was available.</p>";
        }

        var maximum = Math.Max(data.Max(datum => datum.Value), 1);
        const int barHeight = 26;
        const int gap = 8;
        const int labelWidth = 210;
        const int chartWidth = 640;
        var height = (data.Count * (barHeight + gap)) + gap;

        var builder = new StringBuilder(1024);

        builder.Append(CultureInfo.InvariantCulture, $"<figure class=\"chart\" role=\"group\" aria-labelledby=\"{HtmlText.Escape(idPrefix)}-title\">");
        builder.Append(CultureInfo.InvariantCulture,
            $"<svg viewBox=\"0 0 {chartWidth} {height}\" width=\"100%\" height=\"{height}\" role=\"img\" " +
            $"aria-labelledby=\"{HtmlText.Escape(idPrefix)}-title {HtmlText.Escape(idPrefix)}-desc\">");

        builder.Append(CultureInfo.InvariantCulture, $"<title id=\"{HtmlText.Escape(idPrefix)}-title\">{HtmlText.Escape(title)}</title>");
        builder.Append(CultureInfo.InvariantCulture, $"<desc id=\"{HtmlText.Escape(idPrefix)}-desc\">{HtmlText.Escape(description)}</desc>");

        var y = gap;

        foreach (var datum in data)
        {
            var width = (int)Math.Round(datum.Value / maximum * (chartWidth - labelWidth - 60), MidpointRounding.AwayFromZero);
            var colour = HtmlText.CssColor(datum.Colour, "#4b7bb5");

            builder.Append(CultureInfo.InvariantCulture,
                $"<text x=\"0\" y=\"{y + 18}\" class=\"chart-label\">{HtmlText.Escape(Truncate(datum.Label, 32))}</text>");

            builder.Append(CultureInfo.InvariantCulture,
                $"<rect x=\"{labelWidth}\" y=\"{y}\" width=\"{Math.Max(width, 1)}\" height=\"{barHeight}\" " +
                $"fill=\"{colour}\" rx=\"3\" />");

            builder.Append(CultureInfo.InvariantCulture,
                $"<text x=\"{labelWidth + Math.Max(width, 1) + 8}\" y=\"{y + 18}\" class=\"chart-value\">" +
                $"{datum.Value.ToString("0.##", CultureInfo.InvariantCulture)}</text>");

            y += barHeight + gap;
        }

        builder.Append("</svg>");
        builder.Append(TextEquivalent(title, data));
        builder.Append("</figure>");

        return builder.ToString();
    }

    /// <summary>Renders a proportional ring chart with its text equivalent.</summary>
    public static string RingChart(string title, string description, IReadOnlyList<ChartDatum> data, string idPrefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentNullException.ThrowIfNull(data);

        var total = data.Sum(datum => datum.Value);

        if (data.Count == 0 || total <= 0)
        {
            return $"<p class=\"chart-empty\">{HtmlText.Escape(title)}: no data was available.</p>";
        }

        const int size = 220;
        const double radius = 80;
        const double centre = size / 2d;
        const double strokeWidth = 34;
        var circumference = 2 * Math.PI * radius;

        var builder = new StringBuilder(1024);

        builder.Append(CultureInfo.InvariantCulture, $"<figure class=\"chart chart-ring\" role=\"group\" aria-labelledby=\"{HtmlText.Escape(idPrefix)}-title\">");
        builder.Append(CultureInfo.InvariantCulture,
            $"<svg viewBox=\"0 0 {size} {size}\" width=\"{size}\" height=\"{size}\" role=\"img\" " +
            $"aria-labelledby=\"{HtmlText.Escape(idPrefix)}-title {HtmlText.Escape(idPrefix)}-desc\">");

        builder.Append(CultureInfo.InvariantCulture, $"<title id=\"{HtmlText.Escape(idPrefix)}-title\">{HtmlText.Escape(title)}</title>");
        builder.Append(CultureInfo.InvariantCulture, $"<desc id=\"{HtmlText.Escape(idPrefix)}-desc\">{HtmlText.Escape(description)}</desc>");

        double offset = 0;

        foreach (var datum in data)
        {
            var fraction = datum.Value / total;
            var length = fraction * circumference;
            var colour = HtmlText.CssColor(datum.Colour, "#4b7bb5");

            builder.Append(CultureInfo.InvariantCulture,
                $"<circle cx=\"{centre.ToString("0.##", CultureInfo.InvariantCulture)}\" " +
                $"cy=\"{centre.ToString("0.##", CultureInfo.InvariantCulture)}\" " +
                $"r=\"{radius.ToString("0.##", CultureInfo.InvariantCulture)}\" fill=\"none\" " +
                $"stroke=\"{colour}\" stroke-width=\"{strokeWidth}\" " +
                $"stroke-dasharray=\"{length.ToString("0.##", CultureInfo.InvariantCulture)} " +
                $"{(circumference - length).ToString("0.##", CultureInfo.InvariantCulture)}\" " +
                $"stroke-dashoffset=\"{(-offset).ToString("0.##", CultureInfo.InvariantCulture)}\" " +
                $"transform=\"rotate(-90 {centre.ToString("0.##", CultureInfo.InvariantCulture)} " +
                $"{centre.ToString("0.##", CultureInfo.InvariantCulture)})\" />");

            offset += length;
        }

        builder.Append("</svg>");
        builder.Append(TextEquivalent(title, data));
        builder.Append("</figure>");

        return builder.ToString();
    }

    /// <summary>Renders a score card with its numeric value stated in text.</summary>
    public static string ScoreCard(string label, int? value, int coveragePercent, bool isProvisional, string colour)
    {
        var display = value?.ToString(CultureInfo.InvariantCulture) ?? "n/a";
        var safeColour = HtmlText.CssColor(colour, "#1f3a5f");

        var provisional = isProvisional
            ? "<p class=\"score-provisional\">Provisional: weighted collection coverage is below 90%.</p>"
            : string.Empty;

        return $"""
            <div class="score-card" style="border-top-color:{safeColour}">
              <p class="score-label">{HtmlText.Escape(label)}</p>
              <p class="score-value" aria-label="{HtmlText.Escape(label)} score {HtmlText.Escape(display)} out of 100">{HtmlText.Escape(display)}<span class="score-scale">/100</span></p>
              <p class="score-coverage">Coverage {coveragePercent.ToString(CultureInfo.InvariantCulture)}%</p>
              {provisional}
            </div>
            """;
    }

    /// <summary>The table that carries the same numbers as the graphic.</summary>
    private static string TextEquivalent(string title, IReadOnlyList<ChartDatum> data)
    {
        var builder = new StringBuilder(512);

        builder.Append("<figcaption class=\"chart-caption\">");
        builder.Append(HtmlText.Escape(title));
        builder.Append("</figcaption>");
        builder.Append("<table class=\"chart-data\"><caption class=\"visually-hidden\">");
        builder.Append(HtmlText.Escape(title));
        builder.Append(" values</caption><thead><tr><th scope=\"col\">Category</th><th scope=\"col\">Value</th></tr></thead><tbody>");

        foreach (var datum in data)
        {
            builder.Append(CultureInfo.InvariantCulture,
                $"<tr><td>{HtmlText.Escape(datum.Label)}</td><td>{datum.Value.ToString("0.##", CultureInfo.InvariantCulture)}</td></tr>");
        }

        builder.Append("</tbody></table>");

        return builder.ToString();
    }

    private static string Truncate(string value, int maximum) =>
        value.Length <= maximum ? value : value[..(maximum - 1)] + "…";
}
