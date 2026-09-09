using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ipa.Collectors.ActiveDirectory.Collectors;
using Ipa.Collectors.ActiveDirectory.Connection;
using Ipa.Collectors.Entra.Authentication;
using Ipa.Collectors.Entra.Graph;
using Ipa.Collectors.Entra.Permissions;
using Ipa.Collectors.Entra.Preflight;
using Ipa.Contracts;
using Ipa.Desktop.Services;

namespace Ipa.Desktop.ViewModels;

/// <summary>A permission the assessment will request, shown in the registration wizard.</summary>
public sealed record PermissionRow(string Scope, string Purpose, bool IsSensitive);

/// <summary>
/// Configures how the product reaches each source: the directory connection and its transport, and
/// the customer-owned application registration used to sign in to the tenant.
/// </summary>
public sealed partial class ConnectionsViewModel : ViewModelBase, IWorkflowStepViewModel
{
    private readonly AssessmentWorkspace _workspace;
    private readonly MainWindowViewModel _shell;
    private DirectorySession? _directorySession;
    private EntraAuthenticator? _authenticator;
    private GraphReadClient? _graph;

    public ConnectionsViewModel(AssessmentWorkspace workspace, MainWindowViewModel shell)
    {
        _workspace = workspace;
        _shell = shell;

        Permissions = [];
        SetupSteps = new ObservableCollection<string>(AppRegistrationProfile.SetupInstructions);
        RefreshPermissions();
    }

    /// <inheritdoc />
    public override string Title => "Connect to the sources";

    /// <inheritdoc />
    public override string Description =>
        "The assessment is read-only. It issues no write request to the directory or the tenant.";

    // Active Directory connection.

    [ObservableProperty]
    private string _directoryServer = string.Empty;

    [ObservableProperty]
    private bool _useWindowsIntegrated = OperatingSystem.IsWindows();

    [ObservableProperty]
    private string? _directoryUserName;

    [ObservableProperty]
    private string? _directoryDomain;

    [ObservableProperty]
    private string? _directoryPassword;

    [ObservableProperty]
    private DirectoryTransportSecurity _transport = DirectoryTransportSecurity.Ldaps;

    /// <summary>Transport options offered in the interface.</summary>
    public IReadOnlyList<DirectoryTransportSecurity> TransportOptions { get; } =
        Enum.GetValues<DirectoryTransportSecurity>();

    /// <summary>True when Windows integrated authentication cannot be used on this host.</summary>
    public bool IntegratedAuthenticationUnavailable => !OperatingSystem.IsWindows();

    /// <summary>Explains the transport rule that applies to the current selection.</summary>
    public string TransportNotice => UseWindowsIntegrated
        ? "Windows integrated authentication negotiates signing and sealing, so no reusable " +
          "credential is transmitted."
        : "Explicit credentials require LDAPS or StartTLS. This product refuses to send a " +
          "credential over an unprotected connection and never downgrades to an unsigned bind.";

    // Entra registration.

    [ObservableProperty]
    private string _tenantId = string.Empty;

    [ObservableProperty]
    private string _clientId = string.Empty;

    [ObservableProperty]
    private string _redirectUri = "http://localhost";

    [ObservableProperty]
    private string? _adminConsentUrl;

    [ObservableProperty]
    private string? _deviceCodeMessage;

    /// <summary>True once the directory session is open.</summary>
    [ObservableProperty]
    private bool _isDirectoryConnected;

    /// <summary>True once the tenant sign-in has completed.</summary>
    [ObservableProperty]
    private bool _isTenantConnected;

    /// <summary>Steps for creating the customer's application registration.</summary>
    public ObservableCollection<string> SetupSteps { get; }

    /// <summary>The permissions the assessment will request, given the selected check groups.</summary>
    public ObservableCollection<PermissionRow> Permissions { get; }

    /// <summary>Version of the permission manifest, recorded with the assessment.</summary>
    public string PermissionManifestVersion => PermissionManifest.Version;

    /// <summary>True when the assessment includes the Active Directory source.</summary>
    public bool IncludesActiveDirectory => _workspace.Session?.Scope.IncludeActiveDirectory ?? false;

    /// <summary>True when the assessment includes the Entra source.</summary>
    public bool IncludesEntra => _workspace.Session?.Scope.IncludeEntra ?? false;

    /// <inheritdoc />
    public void OnEntered()
    {
        OnPropertyChanged(nameof(IncludesActiveDirectory));
        OnPropertyChanged(nameof(IncludesEntra));
        RefreshPermissions();
    }

    partial void OnUseWindowsIntegratedChanged(bool value)
    {
        OnPropertyChanged(nameof(TransportNotice));
        EnforceTransportRule();
    }

    partial void OnTransportChanged(DirectoryTransportSecurity value) => EnforceTransportRule();

    /// <summary>
    /// Keeps the two selections consistent. Explicit credentials are never sent over a channel
    /// without transport security, so choosing that combination from either direction moves the
    /// transport to LDAPS rather than leaving an unusable pair selected. The connection settings
    /// refuse the combination as well; this keeps the interface from offering it at all.
    /// </summary>
    private void EnforceTransportRule()
    {
        if (!UseWindowsIntegrated && Transport == DirectoryTransportSecurity.SignAndSeal)
        {
            Transport = DirectoryTransportSecurity.Ldaps;
        }
    }

    /// <summary>Validates the directory connection settings without contacting the server.</summary>
    [RelayCommand]
    private void ValidateDirectorySettings()
    {
        ClearMessages();

        try
        {
            var settings = BuildDirectorySettings();
            settings.Validate();

            StatusMessage =
                $"The connection to {settings.Server} on port {settings.EffectivePort} is valid for " +
                $"{settings.AuthenticationMode} over {settings.TransportSecurity}.";
        }
        catch (Exception ex)
        {
            ReportFailure("The directory connection settings are not usable", ex);
        }
    }

    /// <summary>Builds the connection settings from the current selection.</summary>
    public DirectoryConnectionSettings BuildDirectorySettings()
    {
        DirectoryCredential? credential = null;

        if (!UseWindowsIntegrated)
        {
            if (string.IsNullOrWhiteSpace(DirectoryUserName) || string.IsNullOrEmpty(DirectoryPassword))
            {
                throw new InvalidOperationException(
                    "Enter the account name and password for the explicit credential bind.");
            }

            var secure = new System.Security.SecureString();

            foreach (var character in DirectoryPassword)
            {
                secure.AppendChar(character);
            }

            secure.MakeReadOnly();
            credential = new DirectoryCredential(DirectoryUserName, DirectoryDomain ?? string.Empty, secure);
        }

        return new DirectoryConnectionSettings
        {
            Server = DirectoryServer,
            AuthenticationMode = UseWindowsIntegrated
                ? DirectoryAuthenticationMode.WindowsIntegrated
                : DirectoryAuthenticationMode.ExplicitCredentials,
            TransportSecurity = Transport,
            Credential = credential,
        };
    }

    /// <summary>Builds the registration profile from the current selection.</summary>
    public AppRegistrationProfile BuildRegistrationProfile() => new()
    {
        TenantId = TenantId,
        ClientId = ClientId,
        RedirectUri = RedirectUri,
    };

    /// <summary>Validates the registration and produces the administrator consent address.</summary>
    [RelayCommand]
    private void PrepareConsent()
    {
        ClearMessages();

        var profile = BuildRegistrationProfile();
        var problems = profile.Validate();

        if (problems.Count > 0)
        {
            ErrorMessage = string.Join(" ", problems);
            AdminConsentUrl = null;
            return;
        }

        var groups = _workspace.Session?.Scope.SelectedGroups ?? Enum.GetValues<CheckGroup>();

        AdminConsentUrl = profile.BuildAdminConsentUrl(groups);

        StatusMessage =
            "Send the consent address to a Global Administrator in the customer's tenant. " +
            "The registration belongs to the customer, so they can revoke it at any time.";
    }

    /// <summary>Refreshes the permission list for the selected check groups.</summary>
    [RelayCommand]
    private void RefreshPermissions()
    {
        Permissions.Clear();

        var groups = _workspace.Session?.Scope.SelectedGroups ?? Enum.GetValues<CheckGroup>();

        foreach (var permission in PermissionManifest.For(groups))
        {
            Permissions.Add(new PermissionRow(permission.Scope, permission.Purpose, permission.IsSensitive));
        }
    }

    /// <summary>
    /// Opens the directory session. The connection is established once and reused by every Active
    /// Directory collector, so the forest is discovered a single time per assessment.
    /// </summary>
    [RelayCommand]
    private async Task ConnectDirectoryAsync()
    {
        ClearMessages();

        try
        {
            IsBusy = true;

            var settings = BuildDirectorySettings();

            // Opening a session performs network input and output, so it runs off the interface thread.
            var session = await Task.Run(() => DirectorySession.Open(settings)).ConfigureAwait(true);

            _directorySession?.Dispose();
            _directorySession = session;

            IsDirectoryConnected = true;

            StatusMessage =
                $"Connected to the {session.RootDse.DnsHostName ?? settings.Server} forest. " +
                $"Functional level {session.RootDse.ForestFunctionality}, " +
                $"{session.DomainNamingContexts.Count} domain partition(s) discovered.";

            _shell.Collection.AttachSources(_directorySession, _graph);
        }
        catch (Exception ex)
        {
            IsDirectoryConnected = false;
            ReportFailure("The directory connection failed", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Signs in to the tenant and runs the preflight. Tokens live only in memory for the lifetime
    /// of the process and are never written anywhere.
    /// </summary>
    [RelayCommand]
    private async Task ConnectTenantAsync()
    {
        ClearMessages();

        var profile = BuildRegistrationProfile();
        var problems = profile.Validate();

        if (problems.Count > 0)
        {
            ErrorMessage = string.Join(" ", problems);
            return;
        }

        try
        {
            IsBusy = true;

            var authenticator = new EntraAuthenticator(profile);
            var groups = _workspace.Session?.Scope.SelectedGroups ?? Enum.GetValues<CheckGroup>();

            var outcome = await authenticator
                .SignInAsync(
                    groups,
                    message =>
                    {
                        DeviceCodeMessage = message;
                        return Task.CompletedTask;
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            if (!outcome.Succeeded)
            {
                ErrorMessage = outcome.FailureMessage ?? "Sign-in did not complete.";
                await authenticator.DisposeAsync().ConfigureAwait(true);
                return;
            }

            if (_authenticator is not null)
            {
                await _authenticator.DisposeAsync().ConfigureAwait(true);
            }

            _authenticator = authenticator;
            _graph?.Dispose();
            _graph = new GraphReadClient(authenticator.GetAccessTokenAsync, profile.GraphEndpoint);

            IsTenantConnected = true;

            var preflight = await new EntraPreflight(_graph)
                .RunAsync(profile, outcome, groups, CancellationToken.None)
                .ConfigureAwait(true);

            _shell.Preflight.Apply(preflight);
            _shell.Collection.AttachSources(_directorySession, _graph);

            StatusMessage =
                $"Signed in as {outcome.AccountDisplayName}. " +
                (outcome.MissingScopes.Count == 0
                    ? "Every requested permission was granted."
                    : $"{outcome.MissingScopes.Count} permission(s) were not granted; the preflight " +
                      "lists what that affects.");
        }
        catch (Exception ex)
        {
            IsTenantConnected = false;
            ReportFailure("Sign-in failed", ex);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Moves to the preflight step.</summary>
    [RelayCommand]
    private void Continue()
    {
        ClearMessages();
        _shell.GoTo(WorkflowStep.Preflight);
    }

    /// <summary>Closes both connections and discards the tokens held in memory.</summary>
    public async Task DisconnectAsync()
    {
        _directorySession?.Dispose();
        _directorySession = null;

        _graph?.Dispose();
        _graph = null;

        if (_authenticator is not null)
        {
            await _authenticator.DisposeAsync().ConfigureAwait(false);
            _authenticator = null;
        }

        IsDirectoryConnected = false;
        IsTenantConnected = false;
    }
}
