# Testing

## What runs in this repository

```bash
dotnet test IdentityPostureAssessor.slnx
```

| Project | Tests | Covers |
| --- | --- | --- |
| `Ipa.Rules.Tests` | 762 | Pack invariants, per-rule contracts, boundaries, malformed data, scoring |
| `Ipa.Collectors.Tests` | 101 | Parsers, correlation, baseline import, security boundaries |
| `Ipa.Core.Tests` | 46 | Pipeline, end-to-end evaluation, determinism |
| `Ipa.Persistence.Tests` | 41 | Session encryption, container integrity, schema |
| `Ipa.Reporting.Tests` | 37 | Composition, escaping, privacy defaults, PDF rendering |
| `Ipa.Desktop.Tests` | 28 | Headless interface workflow |
| `Ipa.Compliance.Tests` | 18 | Control catalogue and readiness metrics |

### Per-rule coverage

The contract tests run across the **whole pack** by member data, so a rule added later is covered
the moment it is registered. For every rule:

- Missing evidence yields `NotCollected`, never a pass, and the rationale names what was missing.
- Each declared evidence set is genuinely required: withholding it individually yields
  `NotCollected` with the permission reason.
- Evidence marked collected but empty reaches a conclusion rather than an error.
- Results carry the rule identity and version; evaluation is deterministic; the reference instant is
  used rather than the clock; affected-object lists stay bounded.
- An evaluator that throws yields `Error`; cancellation propagates rather than being swallowed.

Boundary tests exercise each threshold rule exactly at its threshold and one step either side.

### Golden fixtures

Parser fixtures are built byte by byte from the documented binary formats rather than captured from
a live system, so the expectations do not depend on any platform tooling and hold identically on
Windows and Linux: `registry.pol`, security templates, security descriptors, access-control entries
and security identifiers.

### Security tests

TLS combinations refused, malformed directory values, zip traversal in baselines and containers,
oversized inputs, corrupt databases, wrong passphrases, tampered manifests and headers, token and
credential redaction, and HTML injection in reports.

### Report rendering

The PDF path is exercised against the real bundled browser and asserts a valid PDF is produced. The
test skips when no browser can be started, so a machine without one still runs the rest of the
suite. Where `CI` is set the environment is expected to provide a browser, so the same condition
fails the test instead: a build that cannot render must not report success with no rendering
coverage.

Setting `IPA_SAMPLE_REPORT_DIR` writes a full sample report from a large synthetic data set, for the
visual check below.

## What this repository cannot run

These require infrastructure that does not exist here. They belong in the release pipeline, and the
acceptance criteria depend on them.

### Multi-domain forest integration

Disposable Windows Server forests containing:

- Multiple domains with external and forest trusts, with and without SID filtering
- Nested privileged groups and delegated access-control entries, including replication rights
- Certificate templates covering the requester-supplied-subject and agent-usage cases
- Representative Group Policy and SYSVOL content, including a preferences file with a stored
  credential

### Entra tenant integration

A dedicated tenant covering Conditional Access, registration state, privileged roles, guests,
applications, consent grants, hybrid identities, deliberately missing permissions, and features the
tenant does not license.

### Cross-platform equivalence

The same directory fixtures assessed from Windows and from Linux, asserting **identical** normalised
evidence, findings and scores. The design supports this - every directory encoding is interpreted by
managed code rather than a platform security type - but only the paired run proves it.

### Visual inspection

Generated PDFs inspected on both platforms with small and very large data sets, checking for clipped
tables, blank pages, orphan headings, missing fonts and unreadable charts.

A fifty-page sample was inspected during development and found two layout defects, both fixed: a
floated cover definition list that overlapped when a term wrapped, and a flexible score-card row
that stretched a trailing card across its own line. That is the exercise this criterion asks for,
repeated per release and on both platforms.

## Regenerating the rule catalogue

`docs/rules.md` is generated from the shipped pack by a test, which fails when it is stale:

```bash
IPA_REGENERATE_DOCS=1 dotnet test tests/Ipa.Rules.Tests --filter CatalogueDocumentMatchesTheShippedPack
```
