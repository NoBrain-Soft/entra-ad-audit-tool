# Acceptance criteria

How each criterion is met, and where the evidence is. Criteria that need infrastructure this
repository does not have are marked as such and are listed in [testing](testing.md).

## No directory or tenant write requests

**Met by construction.** `LdapDirectoryReader` exposes only searches and `GraphReadClient` only
`GET`; neither type has a method that could write. Every permission in the manifest is read-only,
and `SecurityBoundaryTests.EveryRequestedGraphPermissionIsReadOnly` runs the check over the whole
manifest.

Confirming it against a live directory and tenant belongs to integration testing.

## No persisted credentials or tokens

**Met.** No token cache is serialised, so Graph tokens exist only in process memory. The Active
Directory password lives in a `SecureString` for the connection's lifetime. The project passphrase
derives the container key and is discarded, and the interface clears the field afterwards on both
the save and the open path.

The assessment database schema has no column for any of them. Evidence:
`ProjectContainerTests.ContentIsNotRecoverableFromTheContainerBytes`,
`WorkflowTests.OpeningAProjectDiscardsThePassphraseAfterwards`.

## Equivalent Windows and Linux results for protocol-accessible checks

**Designed for; needs a paired run to prove.** Every directory encoding is interpreted by managed
code written against the documented format rather than by a platform security type: security
descriptors, access-control entries, security identifiers, `registry.pol`, security templates,
`userAccountControl`, `groupType` and trust attributes. SYSVOL is read over a managed SMB2 client
with no share mounting.

Golden fixtures built byte by byte from those formats pass on Linux here and are platform-neutral by
construction. The paired-platform run is the remaining step.

## Explicit distinction among fail, unsupported, permission-denied, error and not-applicable

**Met.** Five distinct rule statuses, and `NotCollected` additionally carries the availability
reason - not selected, permission denied, or unsupported. The report's exclusions section states the
status, the reason and the explanation for every rule that was not evaluated.

Evidence: `RuleContractTests.EachDeclaredEvidenceSetIsActuallyRequired`,
`BoundaryConditionTests.OutOfScopeCertificateChecksReportUnavailableRatherThanPassing`,
`EndToEndAssessmentTests.FailAndNotCollectedAreDistinguishableInTheResults`.

## Reproducible scores tied to rule and baseline versions

**Met.** Evaluation is a pure function of the normalised evidence and the rule version, and every
age comparison uses the assessment's fixed reference instant.
`RuleContractTests.EvaluationIsDeterministicForIdenticalEvidence` asserts this per rule, and
`EndToEndAssessmentTests.EvaluationIsDeterministic` across a whole assessment.

The rule-pack version is recorded in the score set, the project manifest and the report. Imported
baselines are recorded by package hash and preserved product and version identity.

## Successful offline PDF generation after collection

**Met.** The document embeds everything it needs, and the browser context runs offline with every
request aborted. `PdfRenderIntegrationTests` renders through the real bundled browser and asserts a
valid PDF. A fifty-page sample was generated and inspected during development.

## Clean uninstall with a separate, explicit choice about deleting saved projects

**Specified; belongs to the installer.** See [release](release.md). The application side is in
place: ephemeral sessions are removed on a normal exit, and any left by a crash are detected at the
next start and offered for deletion, which
`SessionStoreTests.StaleSessionsAreDetectedAndCanBeCleanedUp` covers.

## Additional properties

| Property | Where it is evidenced |
| --- | --- |
| Session data encrypted at rest | `SessionStoreTests.SessionDatabaseIsNotReadableWithoutTheSessionKey` asserts the file lacks the SQLite header |
| Wrong passphrase and tampering are distinguishable | `ProjectContainerTests` covers each failure class separately |
| Annotations never change a score | `EndToEndAssessmentTests.OperatorAnnotationsDoNotChangeTheRawScore` |
| Provider and baseline metrics never blend in | `ScoringEngineTests.BaselineAndSecureScoreGroupsAreExcludedFromPosture` |
| ISO status needs operator confirmation | `ComplianceWorkspaceTests.AutomatedEvidenceSuggestsButNeverSetsAStatus` |
| Reports escape hostile object names | `ReportCompositionTests.HostileObjectNamesAreEscapedRatherThanRendered` |
| Raw evidence excluded unless requested | `ReportCompositionTests.RawAttributesAreExcludedByDefault` |
| Single-source assessments disable the hybrid score | `EndToEndAssessmentTests.ActiveDirectoryOnlyAssessmentDisablesTheHybridScore` |
| A failed collector can be rerun without losing results | `CollectionPipelineTests.RerunningAFailedCollectorRestoresCoverageWithoutLosingOtherResults` |
