# Permissions

## Microsoft Entra

The product signs in through a **public-client application registration in the customer's own
tenant**. The customer creates it, the customer consents to it, and the customer can revoke it. The
product never uses a client secret.

Authentication uses the authorisation code flow with proof key for code exchange through the system
browser, falling back to the device code flow when a loopback listener cannot be opened. See
[MSAL desktop authentication](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/using-web-browsers).

### Creating the registration

1. In the customer's tenant, register a new application under Microsoft Entra ID, App registrations.
2. Choose **Accounts in this organizational directory only**.
3. Under Authentication, add a **Mobile and desktop applications** platform with the redirect
   address `http://localhost`.
4. Enable **Allow public client flows**. Do not create a client secret.
5. Add the delegated Microsoft Graph permissions below, then have a Global Administrator grant
   admin consent.
6. Copy the Directory (tenant) ID and Application (client) ID into the setup wizard.

### Permission manifest

Version **2026.09.1**. Only the permissions the selected check groups need are requested, so an
assessment that skips a group never asks the tenant for that group's permission.

| Permission | Purpose | Sensitive | Required by |
| --- | --- | --- | --- |
| `Directory.Read.All` | Read directory objects, roles, applications and synchronisation attributes | | Privileged access, Conditional Access, applications, directory hygiene, all hybrid groups |
| `RoleManagement.Read.Directory` | Read directory role definitions and assignments | | Privileged access, hybrid privilege exposure |
| `Policy.Read.All` | Read Conditional Access, authentication method policy and federation configuration | | Authentication, Conditional Access, hybrid synchronisation |
| `Application.Read.All` | Read application registrations, service principals and credentials | | Applications |
| `AuditLog.Read.All` | Read sign-in activity for dormancy and legacy authentication | Yes | Privileged access, authentication, directory hygiene |
| `Reports.Read.All` | Read authentication method registration reports | Yes | Authentication |
| `SecurityEvents.Read.All` | Read the Microsoft Secure Score snapshot | Yes | Secure Score |

Every permission is read-only. `PermissionManifest.IsReadOnly` compares whole dot-separated segments
against a verb list, and a test runs it over the entire manifest, so a write permission cannot be
added unnoticed.

### Directory roles

Consent alone is not always enough. Some data also requires a directory role on the signed-in
account:

| Data | Role typically required |
| --- | --- |
| Microsoft Secure Score | Security Reader, Security Administrator or Global Reader |
| Authentication method registration report | Reports Reader or Global Reader |
| Sign-in activity | A premium licence in addition to the permission |

[Secure Score permissions](https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-1.0)
are documented by Microsoft. The **preflight** checks each of these before collection starts and
reports what is missing, what it affects, and what to do about it, so a gap is a decision rather
than a surprise.

### Licence-gated data

Where the tenant does not license a feature, the rules that need it report `NotCollected` and say
so. They never report as passing.

| Feature | Affects |
| --- | --- |
| Premium plan one | Conditional Access policies |
| Premium plan two | Eligible role assignments, identity protection risk signals |

## Active Directory

No special privilege is required beyond reading the directory. Specifically:

| Access | Used for |
| --- | --- |
| Read the domain, configuration and schema partitions | Forest, domains, controllers, sites, trusts, principals |
| Read the discretionary access-control list of tier-zero objects | Delegation and access-control rules |
| Read the Group Policy container and SYSVOL over SMB2 | Group Policy metadata and policy content |
| Read `CN=Public Key Services` in the configuration partition | Certificate templates and enrolment services |

The system access-control list is deliberately **not** requested: reading it needs a privilege this
assessment does not ask for and does not need.

## National clouds

Version one supports the global Microsoft cloud only. The preflight refuses a tenant whose authority
or Graph endpoint is not the global one, rather than partially assessing it.
