using System.Globalization;
using Avalonia.Data.Converters;
using Ipa.Contracts.Text;

namespace Ipa.Desktop.Converters;

/// <summary>
/// Shows an enumeration value as the words a reader expects rather than as its identifier.
/// </summary>
/// <remarks>
/// Without this a grid cell reads "NotAssessed" and a list offers "RemediationPlanned", which is
/// the shape of the code rather than of the product. The same derivation is used by the report,
/// so the interface and the exported document agree on every label.
/// </remarks>
public sealed class EnumLabelConverter : IValueConverter
{
    /// <summary>The shared instance, so a view can reference it without a resource entry.</summary>
    public static readonly EnumLabelConverter Instance = new();

    /// <inheritdoc />
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Enum name ? DisplayText.Humanise(name.ToString()) : value;

    /// <inheritdoc />
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("Labels are shown, never parsed back.");
}
