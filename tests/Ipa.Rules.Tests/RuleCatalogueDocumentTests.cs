using System.Text;
using Ipa.Contracts.Rules;
using Ipa.Rules.Engine;
using Xunit;

namespace Ipa.Rules.Tests;

/// <summary>
/// Generates the rule catalogue document from the pack itself, so the published catalogue cannot
/// drift from the rules that actually ship. The test fails when the checked-in document is stale.
/// </summary>
public sealed class RuleCatalogueDocumentTests
{
    /// <summary>Environment variable that rewrites the document instead of comparing it.</summary>
    public const string RegenerateVariable = "IPA_REGENERATE_DOCS";

    private static string DocumentPath =>
        Path.Combine(RepositoryRoot(), "docs", "rules.md");

    [Fact]
    public void CatalogueDocumentMatchesTheShippedPack()
    {
        var expected = Build(FirstPartyRulePack.Current);

        if (Environment.GetEnvironmentVariable(RegenerateVariable) == "1")
        {
            File.WriteAllText(DocumentPath, expected);
            return;
        }

        Assert.True(File.Exists(DocumentPath), $"The rule catalogue is missing at {DocumentPath}.");

        var actual = File.ReadAllText(DocumentPath).ReplaceLineEndings("\n");

        Assert.True(
            string.Equals(expected, actual, StringComparison.Ordinal),
            $"The rule catalogue is out of date. Regenerate it with {RegenerateVariable}=1.");
    }

    /// <summary>Renders the catalogue as Markdown.</summary>
    public static string Build(IRulePack pack)
    {
        ArgumentNullException.ThrowIfNull(pack);

        var builder = new StringBuilder(32 * 1024);

        builder.Append("# Rule catalogue\n\n");
        builder.Append("Rule pack version **").Append(pack.Version).Append("**, ")
            .Append(pack.Definitions.Count).Append(" rules.\n\n");

        builder.Append("This document is generated from the shipped pack by a test, so it cannot ")
            .Append("drift from the rules that actually run.\n\n");

        builder.Append("## Weights\n\n");
        builder.Append("| Severity | Weight |\n| --- | --- |\n");
        builder.Append("| Critical | ").Append(SeverityWeights.Critical).Append(" |\n");
        builder.Append("| High | ").Append(SeverityWeights.High).Append(" |\n");
        builder.Append("| Medium | ").Append(SeverityWeights.Medium).Append(" |\n");
        builder.Append("| Low | ").Append(SeverityWeights.Low).Append(" |\n");
        builder.Append("| Informational | ").Append(SeverityWeights.Informational)
            .Append(" (never affects a score) |\n\n");

        builder.Append("A rule may declare a weight below its severity band, but never above it.\n\n");

        foreach (var domain in Enum.GetValues<RuleDomain>())
        {
            var inDomain = pack.Definitions.Where(definition => definition.Domain == domain).ToList();

            if (inDomain.Count == 0)
            {
                continue;
            }

            builder.Append("## ").Append(DomainLabel(domain)).Append("\n\n");

            foreach (var group in inDomain.Select(definition => definition.Group).Distinct())
            {
                var inGroup = inDomain
                    .Where(definition => definition.Group == group)
                    .OrderBy(definition => definition.Id.Value, StringComparer.Ordinal)
                    .ToList();

                builder.Append("### ").Append(SplitCamelCase(group.ToString())).Append("\n\n");
                builder.Append("| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |\n");
                builder.Append("| --- | --- | --- | --- | --- |\n");

                foreach (var definition in inGroup)
                {
                    var mappings = string.Join(
                        ", ",
                        definition.FrameworkMappings
                            .Where(mapping => mapping.Framework.StartsWith("ISO", StringComparison.Ordinal))
                            .Select(mapping => mapping.ControlId));

                    builder.Append("| `").Append(definition.Id.Value).Append("` | ")
                        .Append(definition.Title).Append(" | ")
                        .Append(definition.Severity).Append(" | ")
                        .Append(definition.Weight).Append(" | ")
                        .Append(mappings.Length == 0 ? "-" : mappings).Append(" |\n");
                }

                builder.Append('\n');
            }
        }

        builder.Append("## Evidence requirements\n\n");
        builder.Append("Each rule declares the evidence sets it needs. When any is unavailable the ")
            .Append("rule reports `NotCollected` with the reason, and reduces weighted collection ")
            .Append("coverage rather than the score.\n\n");
        builder.Append("| Rule | Required evidence |\n| --- | --- |\n");

        foreach (var definition in pack.Definitions.OrderBy(d => d.Id.Value, StringComparer.Ordinal))
        {
            builder.Append("| `").Append(definition.Id.Value).Append("` | ")
                .Append(string.Join(", ", definition.RequiredEvidence.Select(r => $"`{r.EvidenceKey}`")))
                .Append(" |\n");
        }

        return builder.ToString();
    }

    private static string DomainLabel(RuleDomain domain) => domain switch
    {
        RuleDomain.ActiveDirectory => "Active Directory",
        RuleDomain.Entra => "Microsoft Entra",
        RuleDomain.Hybrid => "Hybrid identity",
        _ => domain.ToString(),
    };

    private static string SplitCamelCase(string value)
    {
        var builder = new StringBuilder(value.Length + 8);

        for (var index = 0; index < value.Length; index++)
        {
            if (index > 0 && char.IsUpper(value[index]) && !char.IsUpper(value[index - 1]))
            {
                builder.Append(' ').Append(char.ToLowerInvariant(value[index]));
                continue;
            }

            builder.Append(value[index]);
        }

        return builder.ToString();
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "README.md")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
               ?? throw new InvalidOperationException("The repository root could not be located.");
    }
}
