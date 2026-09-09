# ISO/IEC 27001 readiness

## What this is, and is not

Everything this product produces for ISO/IEC 27001 is a **readiness assessment**. It is not a
certification, and it is not an audit opinion. That qualifier appears on the metrics, in the
interface, and in the report section, and it is not configurable.

## What is shipped, and what is not

The [standard](https://www.iso.org/standard/27001) is copyright protected. This product ships:

- **Control identifiers** - `A.5.1` through `A.8.34`, ninety-three in total.
- **Labels written by this product**, describing the subject area.
- **Guidance written by this product**, describing what this assessment examines for the control.

It does **not** ship the standard's own control titles or any normative text. An operator who holds
a licence may paste the official wording into a control's licensed-text field; that text stays
inside their own encrypted project and is never part of a release.

The catalogue carries an authorship note stating this, shown above the control list in the
interface and in the report's readiness section.

## Suggestion, then confirmation

Rules carry framework mappings. After evaluation, each control's mapped results produce a
**suggested** status:

| Mapped results | Suggestion |
| --- | --- |
| All passed | Suggest satisfied |
| All failed | Suggest unsatisfied |
| Mixed | Suggest partial |
| None evaluated | No suggestion |

A suggestion is advisory. It never sets the control's status. Only an explicit operator confirmation
does that, and the control records that it was confirmed. A test asserts that automated evidence
alone leaves a control unconfirmed and uncounted.

## Metrics

```
evidence coverage = assessed applicable controls / all applicable controls
readiness         = confirmed satisfied applicable controls / assessed applicable controls
```

Plus the full status distribution: satisfied, partial, unsatisfied, not applicable, not assessed.
The distribution always sums to the whole catalogue, so nothing is quietly dropped.

Controls marked not applicable are excluded from both metrics.

## Per-control working state

Each control holds applicability, owner, status, notes, mapped automated evidence, operator
attestations, attachment references, a review date, and the operator's own licensed text. All of it
lives inside the encrypted session, and inside the encrypted project when one is saved.

## Coverage of the catalogue

Roughly a third of the ninety-three controls have automated evidence: privileged access,
authentication, access control policy, identity lifecycle, configuration management, network
security and cryptography. Physical and people controls are manual by nature, and their guidance
says so plainly rather than implying the tool assessed them.
