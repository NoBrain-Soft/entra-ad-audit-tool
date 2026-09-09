# Scoring

## Weights

Each rule carries a weight derived from its severity band:

| Severity | Weight |
| --- | --- |
| Critical | 10 |
| High | 6 |
| Medium | 3 |
| Low | 1 |
| Informational | 0 |

A rule definition may declare a weight **below** its band, but never above it. `RuleDefinition.Validate`
rejects a pack that tries, and the pack is validated once on load.

## The score

For any scope - a check group, a domain, or the assessment overall:

```
score = round(passed weight / evaluated weight × 100)
```

where *evaluated weight* is the weight of every rule that passed plus every rule that failed. A pass
earns its full weight; a failure earns none. Rounding is away from zero, so 62.5 becomes 63.

The score is **null**, not zero, when nothing in scope could be evaluated. Zero means everything
evaluated failed; null means nothing was evaluated, and the interface and report show them
differently.

## Coverage

```
coverage = evaluated weight / (evaluated + not-collected + errored weight)
```

Rules that do not apply are excluded from **both** sides, because an assessment should not be
penalised for a control that could not arise in the environment.

## Provisional labelling

Coverage below **90%** marks a score provisional. The threshold is inclusive: exactly 90% is not
provisional. Every place a provisional score appears - score card, category table, report summary -
says so, and the report explains that parts of the environment were not assessed and points at the
exclusions section.

## What never moves the score

| Thing | Where it appears instead |
| --- | --- |
| Risk acceptance | An annotation on the finding, in the report |
| False-positive marking | An annotation on the finding, in the report |
| Microsoft Secure Score | Its own attributed metric |
| Baseline conformity | Its own attributed metric |

A finding the operator has dispositioned still contributes exactly as it did before. This is
deliberate: a score that moves when someone writes a justification is not a measurement.

Secure Score and baseline conformity are excluded structurally - their check groups are in
`ScoringEngine.GroupsExcludedFromPosture` - and their rules are informational as well, so neither can
reach the posture score by any route. Both cover a different and larger control set, and blending
them would count several settings twice.

## Scope

- **Both sources connected.** Active Directory, Entra and hybrid scores are all produced.
- **One source connected.** That source's score is produced. Rules for the absent source, and all
  hybrid rules, are `NotApplicable`, so they neither score nor reduce coverage. No score is emitted
  for a scope whose rules were all excluded, which is how the hybrid score reads as disabled rather
  than as zero.
- **A check group deselected inside a connected source.** Its rules are `NotCollected`, which does
  reduce coverage, because that group could have been assessed and was not.

## Reproducibility

Scores are tied to a rule-pack version, recorded in the score set, in the saved project manifest and
on the report cover. Re-evaluating the same evidence with the same pack version reproduces the same
scores exactly, because evaluation is a pure function of the evidence and every age comparison uses
the assessment's fixed reference instant rather than the clock.
