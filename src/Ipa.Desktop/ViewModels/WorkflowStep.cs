namespace Ipa.Desktop.ViewModels;

/// <summary>The steps of the assessment workflow, in the order the operator moves through them.</summary>
public enum WorkflowStep
{
    /// <summary>Start a new assessment, open a project, or clean up after a crash.</summary>
    Welcome,

    /// <summary>Customer and assessor metadata.</summary>
    Details,

    /// <summary>Connect to the Active Directory forest and the Entra tenant.</summary>
    Connections,

    /// <summary>Review what consent, roles and licensing allow before collecting.</summary>
    Preflight,

    /// <summary>Choose which check groups to run.</summary>
    Scope,

    /// <summary>Collect, with progress, cancellation and retry.</summary>
    Collection,

    /// <summary>Inspect findings, scores and coverage.</summary>
    Findings,

    /// <summary>Work the ISO/IEC 27001 readiness controls.</summary>
    Compliance,

    /// <summary>Configure and generate the report.</summary>
    Report,
}
