using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Collectors.Entra.Permissions;
using Ipa.Contracts;
using Ipa.Desktop.Services;
using Ipa.Rules.Engine;

namespace Ipa.Desktop.ViewModels;

/// <summary>A selectable check group.</summary>
public sealed partial class CheckGroupViewModel : ObservableObject
{
    public CheckGroupViewModel(CheckGroup group, string label, int ruleCount, string permissions)
    {
        Group = group;
        Label = label;
        RuleCount = ruleCount;
        Permissions = permissions;
    }

    /// <summary>The group this entry selects.</summary>
    public CheckGroup Group { get; }

    /// <summary>Label shown in the list.</summary>
    public string Label { get; }

    /// <summary>Number of rules in the group.</summary>
    public int RuleCount { get; }

    /// <summary>Permissions the group needs, shown so the operator can weigh the cost of enabling it.</summary>
    public string Permissions { get; }

    /// <summary>True when the group is selected.</summary>
    [ObservableProperty]
    private bool _isSelected = true;
}

/// <summary>
/// Chooses which check groups to run. Only the permissions the selected groups need are requested,
/// so deselecting a group also narrows what the assessment asks the tenant for.
/// </summary>
public sealed partial class ScopeViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;

    public ScopeViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;
        Groups = [];
    }

    /// <inheritdoc />
    public override string Title => "Select check groups";

    /// <inheritdoc />
    public override string Description =>
        "A deselected group is reported as not collected and reduces weighted collection coverage, " +
        "so a partial assessment is always visible in the score.";

    /// <summary>The selectable groups.</summary>
    public ObservableCollection<CheckGroupViewModel> Groups { get; }

    /// <summary>Number of rules the current selection will evaluate.</summary>
    [ObservableProperty]
    private int _selectedRuleCount;

    /// <inheritdoc />
    public void OnEntered()
    {
        if (Groups.Count > 0)
        {
            return;
        }

        var definitions = FirstPartyRulePack.Current.Definitions;
        var session = _workspace.Session;

        foreach (var group in Enum.GetValues<CheckGroup>())
        {
            var applicable = definitions.Where(definition => definition.Group == group).ToList();

            if (applicable.Count == 0)
            {
                continue;
            }

            // A group belonging to a source that is not in scope is not offered at all.
            var domain = applicable[0].Domain;

            var inScope = domain switch
            {
                Contracts.Rules.RuleDomain.ActiveDirectory => session?.Scope.IncludeActiveDirectory ?? true,
                Contracts.Rules.RuleDomain.Entra => session?.Scope.IncludeEntra ?? true,
                Contracts.Rules.RuleDomain.Hybrid => session?.Scope.IncludeHybrid ?? true,
                _ => true,
            };

            if (!inScope)
            {
                continue;
            }

            var permissions = string.Join(", ", PermissionManifest.ScopesFor([group]));

            Groups.Add(new CheckGroupViewModel(
                group,
                Reporting.Html.HtmlReportComposer.SplitCamelCase(group.ToString()),
                applicable.Count,
                permissions.Length == 0 ? "Directory protocol access only" : permissions));
        }

        foreach (var entry in Groups)
        {
            entry.PropertyChanged += (_, _) => RecalculateSelection();
        }

        RecalculateSelection();
    }

    /// <summary>Selects every group.</summary>
    [RelayCommand]
    private void SelectAll()
    {
        foreach (var group in Groups)
        {
            group.IsSelected = true;
        }
    }

    /// <summary>Deselects every group.</summary>
    [RelayCommand]
    private void SelectNone()
    {
        foreach (var group in Groups)
        {
            group.IsSelected = false;
        }
    }

    /// <summary>Applies the selection to the assessment and moves to collection.</summary>
    [RelayCommand]
    private void Continue()
    {
        ClearMessages();

        var selected = Groups.Where(group => group.IsSelected).Select(group => group.Group).ToList();

        if (selected.Count == 0)
        {
            ErrorMessage = "Select at least one check group.";
            return;
        }

        _shell.GoTo(WorkflowStep.Collection);
    }

    /// <summary>The groups the operator has selected.</summary>
    public IReadOnlyCollection<CheckGroup> SelectedGroups =>
        Groups.Where(group => group.IsSelected).Select(group => group.Group).ToList();

    private void RecalculateSelection() =>
        SelectedRuleCount = Groups.Where(group => group.IsSelected).Sum(group => group.RuleCount);
}
