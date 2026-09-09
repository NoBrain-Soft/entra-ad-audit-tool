using Ipa.Contracts;
using Ipa.Contracts.Evidence;
using Ipa.Contracts.Rules;

namespace Ipa.Rules.Engine;

/// <summary>Helpers shared by rule implementations for building results consistently.</summary>
public static class RuleHelpers
{
    /// <summary>Maximum affected objects a rule records. Keeps results and reports bounded.</summary>
    public const int MaxAffectedObjects = 200;

    /// <summary>Creates an affected object for an Active Directory principal.</summary>
    public static AffectedObject ForPrincipal(AdPrincipal principal, string? detail = null) => new()
    {
        Identifier = principal.Sid,
        DisplayName = principal.SamAccountName,
        ObjectType = principal.ObjectClass ?? "user",
        Source = AssessmentSource.ActiveDirectory,
        Detail = detail,
    };

    /// <summary>Creates an affected object for an Active Directory computer.</summary>
    public static AffectedObject ForComputer(AdComputer computer, string? detail = null) => new()
    {
        Identifier = computer.Sid,
        DisplayName = computer.SamAccountName,
        ObjectType = "computer",
        Source = AssessmentSource.ActiveDirectory,
        Detail = detail,
    };

    /// <summary>Creates an affected object for an Active Directory group.</summary>
    public static AffectedObject ForGroup(AdGroup group, string? detail = null) => new()
    {
        Identifier = group.Sid,
        DisplayName = group.SamAccountName,
        ObjectType = "group",
        Source = AssessmentSource.ActiveDirectory,
        Detail = detail,
    };

    /// <summary>Creates an affected object for a Group Policy object.</summary>
    public static AffectedObject ForGpo(GroupPolicyObject gpo, string? detail = null) => new()
    {
        Identifier = gpo.Guid,
        DisplayName = gpo.DisplayName,
        ObjectType = "groupPolicyObject",
        Source = AssessmentSource.ActiveDirectory,
        Detail = detail,
    };

    /// <summary>Creates an affected object for an Entra user.</summary>
    public static AffectedObject ForEntraUser(EntraUser user, string? detail = null) => new()
    {
        Identifier = user.ObjectId,
        DisplayName = user.UserPrincipalName,
        ObjectType = user.UserType.Equals("Guest", StringComparison.OrdinalIgnoreCase) ? "guest" : "user",
        Source = AssessmentSource.Entra,
        Detail = detail,
    };

    /// <summary>Creates an affected object for an arbitrary Entra directory object.</summary>
    public static AffectedObject ForEntraObject(
        string objectId,
        string displayName,
        string objectType,
        string? detail = null) => new()
    {
        Identifier = objectId,
        DisplayName = displayName,
        ObjectType = objectType,
        Source = AssessmentSource.Entra,
        Detail = detail,
    };

    /// <summary>Caps a list of affected objects and notes how many were omitted.</summary>
    public static IReadOnlyList<AffectedObject> Cap(IEnumerable<AffectedObject> objects)
    {
        var list = objects.Take(MaxAffectedObjects + 1).ToList();
        if (list.Count <= MaxAffectedObjects)
        {
            return list;
        }

        list.RemoveAt(list.Count - 1);
        list.Add(new AffectedObject
        {
            Identifier = "truncated",
            DisplayName = $"... additional objects beyond the first {MaxAffectedObjects} are not listed",
            ObjectType = "note",
            Sensitivity = Sensitivity.Summary,
        });

        return list;
    }

    /// <summary>Age in whole days between a timestamp and the fixed reference instant.</summary>
    public static double? AgeInDays(DateTimeOffset? timestamp, DateTimeOffset referenceTime) =>
        timestamp is null ? null : (referenceTime - timestamp.Value).TotalDays;

    /// <summary>True when the timestamp is older than the supplied number of days, or absent.</summary>
    public static bool IsStale(DateTimeOffset? timestamp, DateTimeOffset referenceTime, int days) =>
        timestamp is null || (referenceTime - timestamp.Value).TotalDays > days;
}
