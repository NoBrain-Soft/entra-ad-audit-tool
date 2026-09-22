# Rule catalogue

Rule pack version **2026.09.1**, 86 rules.

This document is generated from the shipped pack by a test, so it cannot drift from the rules that actually run.

## Weights

| Severity | Weight |
| --- | --- |
| Critical | 10 |
| High | 6 |
| Medium | 3 |
| Low | 1 |
| Informational | 0 (never affects a score) |

A rule may declare a weight below its severity band, but never above it.

## Active Directory

### AD privileged access

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-PRIV-001` | Tier-zero group membership is limited | High | 6 | A.8.2, A.5.18 |
| `AD-PRIV-002` | Tier-zero groups contain no nested groups | High | 6 | A.8.2 |
| `AD-PRIV-003` | Tier-zero accounts have no service principal name | Critical | 10 | A.8.2, A.5.17 |
| `AD-PRIV-004` | Tier-zero accounts are protected against credential theft | Medium | 3 | A.8.2 |
| `AD-PRIV-005` | No dormant tier-zero accounts | High | 6 | A.5.18, A.8.2 |
| `AD-PRIV-006` | Tier-zero credentials are rotated | Medium | 3 | A.5.17 |
| `AD-PRIV-007` | No accounts retain protected-account status after losing privilege | Low | 1 | A.5.18 |

### AD account hygiene

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-ACCT-001` | Enabled user accounts are in active use | Medium | 3 | A.5.18 |
| `AD-ACCT-002` | Enabled accounts are subject to password expiry | Medium | 3 | A.5.17 |
| `AD-ACCT-003` | No enabled account may have an empty password | High | 6 | A.5.17 |
| `AD-ACCT-004` | Kerberos pre-authentication is required | High | 6 | A.5.17 |
| `AD-ACCT-005` | No residual SID history on accounts | Medium | 3 | A.5.18 |
| `AD-ACCT-006` | Computer accounts are in active use | Low | 1 | A.8.9 |
| `AD-ACCT-007` | No domain-joined systems run an unsupported operating system | High | 6 | A.8.8 |

### AD delegation and ACL

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-DELEG-001` | Unconstrained delegation is limited to domain controllers | Critical | 10 | A.8.2, A.8.9 |
| `AD-DELEG-002` | Constrained delegation does not permit protocol transition | High | 6 | A.8.2 |
| `AD-DELEG-003` | Directory replication rights are restricted to tier zero | Critical | 10 | A.8.2, A.5.17 |
| `AD-DELEG-004` | Tier-zero objects are not writable by non-privileged principals | Critical | 10 | A.8.3, A.8.2 |
| `AD-DELEG-005` | The protected-account template has no unexpected delegation | High | 6 | A.8.2 |

### AD domain policy

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-POL-001` | Minimum password length is sufficient | Medium | 3 | A.5.17 |
| `AD-POL-002` | Password complexity is enforced | Medium | 3 | A.5.17 |
| `AD-POL-003` | Passwords are not stored with reversible encryption | High | 6 | A.5.17, A.8.24 |
| `AD-POL-004` | Account lockout is configured | Medium | 3 | A.8.5 |
| `AD-POL-005` | Password history prevents immediate reuse | Low | 1 | A.5.17 |
| `AD-POL-006` | The Kerberos key distribution account is rotated | High | 6 | A.5.17, A.8.24 |
| `AD-POL-007` | Ordinary users cannot create computer accounts | Medium | 3 | A.8.2 |
| `AD-POL-008` | Domain functional level is current | Medium | 3 | A.8.8 |
| `AD-POL-009` | The directory recycle bin is enabled | Low | 1 | A.8.13 |

### AD trusts and topology

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-TOPO-001` | Forest functional level is current | Medium | 3 | A.8.8 |
| `AD-TOPO-002` | Each domain has redundant domain controllers | Medium | 3 | A.8.14 |
| `AD-TOPO-003` | Replication sites are correctly defined | Low | 1 | A.8.9 |
| `AD-TRUST-001` | SID filtering is enabled on external and forest trusts | High | 6 | A.5.19, A.8.2 |
| `AD-TRUST-002` | External trusts use selective authentication | Medium | 3 | A.5.19 |

### AD group policy

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-GPO-001` | Group Policy objects are not writable by non-privileged principals | Critical | 10 | A.8.2, A.8.9 |
| `AD-GPO-002` | No Group Policy Preferences file stores a credential | Critical | 10 | A.5.17, A.8.24 |
| `AD-GPO-003` | Group Policy objects are linked and version consistent | Low | 1 | A.8.9 |
| `AD-GPO-004` | Domain controllers require LDAP signing | High | 6 | A.8.20, A.8.24 |
| `AD-GPO-005` | Domain controllers enforce LDAP channel binding | High | 6 | A.8.20 |
| `AD-GPO-006` | SMB signing is required on servers | High | 6 | A.8.20 |
| `AD-GPO-007` | Legacy LAN Manager authentication is refused | Medium | 3 | A.8.5 |
| `AD-GPO-008` | SMB version one is disabled | High | 6 | A.8.8 |
| `AD-GPO-009` | Sensitive privilege rights are restricted | Medium | 3 | A.8.2 |

### AD certificate services

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `AD-CS-001` | No enrollable template allows a requester-supplied subject for authentication | Critical | 10 | A.8.24, A.5.17 |
| `AD-CS-002` | No broadly enrollable template grants an unrestricted or enrolment-agent usage | High | 6 | A.8.24 |
| `AD-CS-003` | Certificate templates and authorities are controlled by tier zero | High | 6 | A.8.2 |
| `AD-CS-900` | Certificate authority host checks are outside the read-only scope | Informational | 0 | A.8.8 |

### Baseline conformity

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `BAS-001` | Group Policy conformity with the imported Microsoft baseline | Informational | 0 | A.8.9 |

## Microsoft Entra

### Entra privileged access

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `EID-PRIV-001` | Global Administrator count is within the recommended range | High | 6 | A.8.2, A.5.18 |
| `EID-PRIV-002` | Privileged roles are activated just in time | High | 6 | A.8.2 |
| `EID-PRIV-003` | Guest accounts hold no privileged directory role | Critical | 10 | A.5.19, A.8.2 |
| `EID-PRIV-004` | Privileged accounts are registered for strong authentication | Critical | 10 | A.8.5, A.8.2 |
| `EID-PRIV-005` | No dormant privileged accounts | High | 6 | A.5.18 |
| `EID-PRIV-006` | Emergency access accounts exist and are excluded from access policy | High | 6 | A.5.29, A.8.2 |
| `EID-PRIV-007` | Service principals hold no high-privilege directory role | High | 6 | A.8.2 |

### Entra authentication

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `EID-AUTH-001` | Strong authentication registration covers the member population | High | 6 | A.8.5 |
| `EID-AUTH-002` | Legacy authentication is blocked by Conditional Access | Critical | 10 | A.8.5, A.8.20 |
| `EID-AUTH-003` | No successful legacy authentication is observed | High | 6 | A.8.16 |
| `EID-AUTH-004` | Phishing-resistant authentication methods are enabled | Medium | 3 | A.8.5 |
| `EID-AUTH-005` | The tenant enforces a baseline authentication control | High | 6 | A.8.5 |
| `EID-AUTH-006` | Legacy per-user multi-factor state is not in use | Medium | 3 | A.8.9 |

### Entra conditional access

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `EID-CA-001` | Multi-factor authentication is required for all users | Critical | 10 | A.8.5, A.5.15 |
| `EID-CA-002` | Administrative roles are covered by a multi-factor policy | Critical | 10 | A.8.2 |
| `EID-CA-003` | Conditional Access exclusions are limited | Medium | 3 | A.5.15 |
| `EID-CA-004` | Report-only policies are not left unenforced indefinitely | Low | 1 | A.5.15 |
| `EID-CA-005` | Risk-based access policies are configured | Medium | 3 | A.8.16 |
| `EID-CA-006` | A device requirement constrains access | Medium | 3 | A.8.1 |

### Entra applications

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `EID-APP-001` | Application credentials are current and short lived | Medium | 3 | A.5.17 |
| `EID-APP-002` | No application credential expires imminently | Low | 1 | A.5.17 |
| `EID-APP-003` | High-impact application permissions are not broadly granted | Critical | 10 | A.8.2, A.5.23 |
| `EID-APP-004` | Tenant-wide consent is limited to low-impact scopes | High | 6 | A.5.23 |
| `EID-APP-005` | Application registrations have an owner | Low | 1 | A.5.9 |
| `EID-APP-006` | Application sign-in audience is restricted to this tenant | Medium | 3 | A.5.23 |

### Entra directory hygiene

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `EID-DIR-001` | Enabled member accounts are in active use | Medium | 3 | A.5.18 |
| `EID-DIR-002` | Guest accounts are reviewed and removed | Medium | 3 | A.5.18, A.5.19 |
| `EID-DIR-003` | Registered devices are in active use | Low | 1 | A.5.9 |
| `EID-DIR-004` | Disabled accounts are removed after retention | Low | 1 | A.5.11 |

### Entra secure score

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `EID-SS-001` | Microsoft Secure Score is reported separately | Informational | 0 | A.5.36 |

## Hybrid identity

### Hybrid identity correlation

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `HYB-COR-001` | Synchronisation anchors are unique | High | 6 | A.5.16 |
| `HYB-COR-002` | Synchronised cloud objects have a matching directory object | Medium | 3 | A.5.16 |
| `HYB-COR-003` | Hybrid correlation has no unresolved ambiguity | Low | 1 | A.5.16 |

### Hybrid privilege exposure

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `HYB-PRIV-001` | Cloud privilege is not held by synchronised accounts | Critical | 10 | A.8.2, A.5.23 |
| `HYB-PRIV-002` | Directory synchronisation accounts are protected | High | 6 | A.8.2 |
| `HYB-PRIV-003` | On-premises tier-zero accounts are not synchronised | High | 6 | A.8.2 |

### Hybrid synchronisation

| Rule | Title | Severity | Weight | ISO/IEC 27001:2022 |
| --- | --- | --- | --- | --- |
| `HYB-SYNC-001` | Directory synchronisation is current | Medium | 3 | A.5.18 |
| `HYB-SYNC-002` | Federation signing certificates are current | High | 6 | A.8.24 |
| `HYB-SYNC-003` | Federated domains support multi-factor claims | Medium | 3 | A.8.5 |

## Evidence requirements

Each rule declares the evidence sets it needs. When any is unavailable the rule reports `NotCollected` with the reason, and reduces weighted collection coverage rather than the score.

| Rule | Required evidence |
| --- | --- |
| `AD-ACCT-001` | `ad.users` |
| `AD-ACCT-002` | `ad.users` |
| `AD-ACCT-003` | `ad.users` |
| `AD-ACCT-004` | `ad.users` |
| `AD-ACCT-005` | `ad.users` |
| `AD-ACCT-006` | `ad.computers` |
| `AD-ACCT-007` | `ad.computers` |
| `AD-CS-001` | `ad.certificateServices`, `ad.groups`, `ad.users`, `ad.domains` |
| `AD-CS-002` | `ad.certificateServices`, `ad.groups`, `ad.users`, `ad.domains` |
| `AD-CS-003` | `ad.certificateServices`, `ad.groups`, `ad.users`, `ad.domains` |
| `AD-CS-900` | `ad.certificateServices` |
| `AD-DELEG-001` | `ad.computers`, `ad.users` |
| `AD-DELEG-002` | `ad.computers`, `ad.users` |
| `AD-DELEG-003` | `ad.acls`, `ad.groups`, `ad.users`, `ad.domains` |
| `AD-DELEG-004` | `ad.acls`, `ad.groups`, `ad.users`, `ad.domains` |
| `AD-DELEG-005` | `ad.acls`, `ad.domains`, `ad.groups`, `ad.users` |
| `AD-GPO-001` | `ad.groupPolicy`, `ad.groups`, `ad.users`, `ad.domains` |
| `AD-GPO-002` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-003` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-004` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-005` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-006` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-007` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-008` | `ad.groupPolicy`, `ad.sysvol` |
| `AD-GPO-009` | `ad.groupPolicy`, `ad.sysvol`, `ad.groups`, `ad.domains`, `ad.users` |
| `AD-POL-001` | `ad.passwordPolicy`, `ad.domains` |
| `AD-POL-002` | `ad.passwordPolicy`, `ad.domains` |
| `AD-POL-003` | `ad.passwordPolicy`, `ad.domains` |
| `AD-POL-004` | `ad.passwordPolicy`, `ad.domains` |
| `AD-POL-005` | `ad.passwordPolicy`, `ad.domains` |
| `AD-POL-006` | `ad.domains` |
| `AD-POL-007` | `ad.domains` |
| `AD-POL-008` | `ad.domains` |
| `AD-POL-009` | `ad.domains` |
| `AD-PRIV-001` | `ad.groups`, `ad.users`, `ad.domains` |
| `AD-PRIV-002` | `ad.groups`, `ad.domains` |
| `AD-PRIV-003` | `ad.users`, `ad.groups`, `ad.domains` |
| `AD-PRIV-004` | `ad.users`, `ad.groups`, `ad.domains` |
| `AD-PRIV-005` | `ad.users`, `ad.groups`, `ad.domains` |
| `AD-PRIV-006` | `ad.users`, `ad.groups`, `ad.domains` |
| `AD-PRIV-007` | `ad.users`, `ad.groups`, `ad.domains` |
| `AD-TOPO-001` | `ad.forest` |
| `AD-TOPO-002` | `ad.domains`, `ad.sites` |
| `AD-TOPO-003` | `ad.sites` |
| `AD-TRUST-001` | `ad.trusts` |
| `AD-TRUST-002` | `ad.trusts` |
| `BAS-001` | `baseline.comparison` |
| `EID-APP-001` | `entra.applications` |
| `EID-APP-002` | `entra.applications` |
| `EID-APP-003` | `entra.servicePrincipals` |
| `EID-APP-004` | `entra.servicePrincipals` |
| `EID-APP-005` | `entra.applications` |
| `EID-APP-006` | `entra.applications` |
| `EID-AUTH-001` | `entra.users`, `entra.registrationDetails` |
| `EID-AUTH-002` | `entra.conditionalAccess` |
| `EID-AUTH-003` | `entra.legacyAuthentication` |
| `EID-AUTH-004` | `entra.authenticationMethods` |
| `EID-AUTH-005` | `entra.authenticationMethods`, `entra.conditionalAccess` |
| `EID-AUTH-006` | `entra.authenticationMethods` |
| `EID-CA-001` | `entra.conditionalAccess` |
| `EID-CA-002` | `entra.conditionalAccess`, `entra.roleAssignments` |
| `EID-CA-003` | `entra.conditionalAccess` |
| `EID-CA-004` | `entra.conditionalAccess` |
| `EID-CA-005` | `entra.conditionalAccess`, `entra.tenant` |
| `EID-CA-006` | `entra.conditionalAccess` |
| `EID-DIR-001` | `entra.users`, `entra.signInActivity` |
| `EID-DIR-002` | `entra.users`, `entra.signInActivity` |
| `EID-DIR-003` | `entra.devices` |
| `EID-DIR-004` | `entra.users` |
| `EID-PRIV-001` | `entra.roleAssignments` |
| `EID-PRIV-002` | `entra.roleAssignments`, `entra.pim` |
| `EID-PRIV-003` | `entra.roleAssignments`, `entra.users` |
| `EID-PRIV-004` | `entra.roleAssignments`, `entra.users`, `entra.registrationDetails` |
| `EID-PRIV-005` | `entra.roleAssignments`, `entra.users`, `entra.signInActivity` |
| `EID-PRIV-006` | `entra.roleAssignments`, `entra.users`, `entra.conditionalAccess` |
| `EID-PRIV-007` | `entra.roleAssignments`, `entra.servicePrincipals` |
| `EID-SS-001` | `entra.secureScore` |
| `HYB-COR-001` | `hybrid.matches` |
| `HYB-COR-002` | `hybrid.matches` |
| `HYB-COR-003` | `hybrid.matches` |
| `HYB-PRIV-001` | `hybrid.matches`, `entra.roleAssignments` |
| `HYB-PRIV-002` | `hybrid.sync` |
| `HYB-PRIV-003` | `hybrid.matches`, `ad.groups`, `ad.users`, `ad.domains` |
| `HYB-SYNC-001` | `hybrid.sync` |
| `HYB-SYNC-002` | `hybrid.federation` |
| `HYB-SYNC-003` | `hybrid.federation` |
