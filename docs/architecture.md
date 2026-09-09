# Architecture

## Project boundaries

The solution is split so that nothing about how an assessment is *presented* can affect what it
*concludes*.

```
Ipa.Desktop  ──▶ Ipa.Core ──▶ Ipa.Rules ──▶ Ipa.Contracts
   (Avalonia)        │     ├─▶ Ipa.Compliance
                     │     ├─▶ Ipa.Collectors.{ActiveDirectory,Entra,Hybrid}
                     │     ├─▶ Ipa.Persistence
                     │     └─▶ Ipa.Reporting
```

`Ipa.Contracts` sits at the bottom and references nothing. Every other library references it, and
none of them reference Avalonia. That is what makes a future command-line or service front end
possible without touching rule semantics: it would replace `Ipa.Desktop` only.

## The collection pipeline

Collection runs in ordered stages:

1. **Discovery** – the directory and the tenant. Everything else builds on these.
2. **Detail** – Group Policy, certificate services, access policy, applications, Secure Score.
3. **Correlation** – hybrid matching, which needs both sources.

Within a stage, collectors that read the *same source* run in sequence, because each contributes to
one shared evidence fragment and a concurrent write would lose a contribution. Collectors reading
*different* sources run in parallel under a bounded degree.

A collector that fails does not stop the run. Its evidence sets are marked unavailable with a
reason, so the rules that depend on them report `NotCollected` rather than passing on absent data,
and the collector can be rerun on its own afterwards without discarding results that succeeded.

## Determinism

Two properties make an assessment reproducible:

- **A fixed reference instant.** Every age comparison in every rule uses the instant recorded when
  the assessment was created, not the wall clock. A test asserts this across the whole pack.
- **Pure evaluation.** `IRuleEvaluator` implementations perform no input or output. They read the
  normalised evidence and nothing else.

Together these mean that re-evaluating the same evidence with the same rule-pack version produces
byte-identical results, which is what lets a saved project reproduce the scores it was saved with.

## Evidence model

Collectors produce **normalised evidence**: strongly typed, platform-neutral records. All
interpretation of directory encodings - `userAccountControl` flags, `groupType` bit fields, trust
attributes, binary security descriptors, security identifiers - happens in the collectors, so the
same forest yields identical evidence whether the assessment ran from Windows or from Linux.

Alongside the data, evidence carries an **availability map**: for each named evidence set, whether
it was collected, not selected, denied, unsupported, or errored. Rules consult it before evaluating,
which is what makes "not collected" a first-class outcome rather than an absence that looks like a
pass.

## Status semantics

| Status | Meaning | Effect on score | Effect on coverage |
| --- | --- | --- | --- |
| `Pass` | The control is in place | Earns full weight | Counts as evaluated |
| `Fail` | The control is missing or misconfigured | Earns zero weight | Counts as evaluated |
| `NotApplicable` | The rule cannot apply to this environment | Excluded entirely | Excluded entirely |
| `NotCollected` | Required evidence was not collected | Excluded from the denominator | **Reduces coverage** |
| `Error` | Evaluation failed unexpectedly | Excluded from the denominator | **Reduces coverage** |

A source that is not connected produces `NotApplicable`, because the assessment was never meant to
cover it. A check group the operator deselected inside a connected source produces `NotCollected`,
because it could have been covered and was not.
