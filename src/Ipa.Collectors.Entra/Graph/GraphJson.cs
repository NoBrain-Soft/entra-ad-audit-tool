using System.Globalization;
using System.Text.Json;

namespace Ipa.Collectors.Entra.Graph;

/// <summary>Reads values from Microsoft Graph JSON with the tolerance a service response needs.</summary>
public static class GraphJson
{
    /// <summary>Returns a string property, or null when it is absent or JSON null.</summary>
    public static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>Returns a boolean property, or null when it is absent.</summary>
    public static bool? Boolean(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value)
            ? value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => null,
            }
            : null;

    /// <summary>Returns a timestamp property, or null when it is absent or unparsable.</summary>
    public static DateTimeOffset? Timestamp(JsonElement element, string name)
    {
        var raw = String(element, name);

        return DateTimeOffset.TryParse(
            raw,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    /// <summary>Returns a numeric property as a double, or null when it is absent.</summary>
    public static double? Number(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
            ? value.GetDouble()
            : null;

    /// <summary>Returns the string members of an array property, skipping non-string entries.</summary>
    public static IReadOnlyList<string> Strings(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var items = new List<string>();

        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } text)
            {
                items.Add(text);
            }
        }

        return items;
    }

    /// <summary>Returns the object members of an array property.</summary>
    public static IReadOnlyList<JsonElement> Objects(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return value.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.Object)
            .Select(item => item.Clone())
            .ToList();
    }

    /// <summary>Returns a nested object property, or null when it is absent.</summary>
    public static JsonElement? Object(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Object
            ? value
            : null;

    /// <summary>
    /// Reads the property values of an object collection, such as the string identifiers in a
    /// Conditional Access condition set.
    /// </summary>
    public static IReadOnlyList<string> NestedStrings(JsonElement element, string objectName, string arrayName)
    {
        var nested = Object(element, objectName);
        return nested is null ? [] : Strings(nested.Value, arrayName);
    }
}
