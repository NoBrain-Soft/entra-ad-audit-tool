# Identity Posture Assessor

A commercial Windows and Linux desktop tool that assesses the identity posture of one Active
Directory forest and one Microsoft Entra tenant, correlates the hybrid identities between them, and
produces a white-label PDF report.

The product name is configurable centrally in
[`ProductInfo`](src/Ipa.Contracts/ProductInfo.cs) so a release can be re-branded without touching
feature code.

## What it does

- Assesses **one Active Directory forest and one Entra tenant** per session, and correlates the
  hybrid identities between them.
- Runs a **versioned first-party rule pack** and produces separate Active Directory, Entra, hybrid
  and overall posture scores.
- Compares domain Group Policy with a **Microsoft Security Compliance Toolkit baseline** the
  operator supplies.
- Maintains **ISO/IEC 27001 readiness** from automated evidence mappings plus operator attestations.
- Generates a configurable **offline PDF** locally.
- Keeps assessments **ephemeral** unless the operator explicitly saves an encrypted project.

## What it deliberately does not do

The assessment is strictly read-only. There is no code path that writes to a directory or a tenant:

- Directory access goes through a reader that exposes only searches. There is no add, modify or
  delete method for a collector to call.
- Cloud access goes through a client that exposes only `GET`. Every permission in the
  [permission manifest](src/Ipa.Collectors.Entra/Permissions/PermissionManifest.cs) is read-only,
  and a test asserts it.
- No remediation is executed, no server is probed, and there is no CLI, REST API or cloud backend in
  version one.

Checks that would require probing a certification authority host or reading a server registry are
reported as **unavailable**, never as passing.

## Getting started

```bash
dotnet build IdentityPostureAssessor.slnx
dotnet test  IdentityPostureAssessor.slnx
dotnet run --project src/Ipa.Desktop
```

Requires the [.NET 10 SDK](https://learn.microsoft.com/en-us/dotnet/core/releases-and-support).
.NET 10 is a long-term support release supported through November 2028.

## Solution layout

| Project | Responsibility |
| --- | --- |
| `Ipa.Contracts` | Shared contracts: collectors, rules, evidence, findings, scoring, reporting. No UI dependency. |
| `Ipa.Rules` | The first-party rule pack, the rule engine and the scoring engine. |
| `Ipa.Compliance` | ISO/IEC 27001 readiness workspace and control catalogue. |
| `Ipa.Collectors.ActiveDirectory` | LDAP, SYSVOL, Group Policy, AD CS and baseline import. |
| `Ipa.Collectors.Entra` | MSAL authentication, permission manifest, Graph client, preflight. |
| `Ipa.Collectors.Hybrid` | Hybrid identity correlation. |
| `Ipa.Persistence` | Ephemeral SQLCipher session store and the encrypted project container. |
| `Ipa.Reporting` | Deterministic HTML composition and Playwright PDF rendering. |
| `Ipa.Core` | Assessment orchestration and the staged collection pipeline. |
| `Ipa.Desktop` | The Avalonia desktop application. |

Collectors, evaluators, evidence contracts and report profiles are all independent of Avalonia, so a
future command-line or service front end can reuse them without changing rule semantics.

## Documentation

| Document | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Project boundaries, the collection pipeline, determinism. |
| [Security model](docs/security-model.md) | Transport rules, credential handling, encryption, redaction. |
| [Permissions](docs/permissions.md) | The Graph permission manifest and the directory access needed. |
| [Rule catalogue](docs/rules.md) | Every rule, its severity, weight and framework mapping. |
| [Scoring](docs/scoring.md) | Exactly how scores, coverage and provisional labelling are computed. |
| [ISO readiness](docs/iso-readiness.md) | What is shipped, what is not, and how readiness is measured. |
| [Reporting](docs/reporting.md) | Sections, white-label fields and the privacy defaults. |
| [Testing](docs/testing.md) | What is covered, and the integration testing this repository cannot run. |
| [Release](docs/release.md) | Signing, packaging, SBOM and the supported platforms. |
| [Acceptance](docs/acceptance.md) | The acceptance criteria and how each one is evidenced. |

## Licence and third-party material

See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The product redistributes neither Microsoft
security baseline packages nor ISO/IEC standard text; both are supplied by the operator from their
own licensed copy.
