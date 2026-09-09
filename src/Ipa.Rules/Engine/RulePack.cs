using Ipa.Contracts.Rules;

namespace Ipa.Rules.Engine;

/// <summary>
/// A versioned set of rules. Version one ships exactly one first-party pack, embedded in the
/// signed application release: the product never loads rule code from disk or from an operator,
/// so a report's scores can always be tied to a signed pack version.
/// </summary>
public interface IRulePack
{
    /// <summary>Version of the pack, recorded in every score set, report and saved project.</summary>
    string Version { get; }

    /// <summary>Every rule in the pack, including withdrawn rules retained for history.</summary>
    IReadOnlyList<RuleBase> Rules { get; }

    /// <summary>Definitions of every rule in the pack.</summary>
    IReadOnlyList<RuleDefinition> Definitions { get; }
}

/// <summary>Validates the structural invariants a rule pack must satisfy.</summary>
public static class RulePackValidator
{
    /// <summary>Throws when the pack violates an invariant; returns the pack otherwise.</summary>
    public static IRulePack Validate(IRulePack pack)
    {
        ArgumentNullException.ThrowIfNull(pack);

        if (string.IsNullOrWhiteSpace(pack.Version))
        {
            throw new InvalidOperationException("A rule pack must declare a version.");
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in pack.Rules)
        {
            var definition = rule.Definition;
            definition.Validate();

            if (!seen.Add(definition.Id.Value))
            {
                throw new InvalidOperationException($"Duplicate rule identifier {definition.Id}.");
            }

            if (!string.Equals(rule.RuleId.Value, definition.Id.Value, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Rule {definition.Id} exposes a mismatched evaluator identifier {rule.RuleId}.");
            }

            foreach (var requirement in definition.RequiredEvidence)
            {
                if (!Contracts.Evidence.EvidenceKeys.All.Contains(requirement.EvidenceKey))
                {
                    throw new InvalidOperationException(
                        $"Rule {definition.Id} requires unknown evidence key '{requirement.EvidenceKey}'.");
                }
            }
        }

        return pack;
    }
}
