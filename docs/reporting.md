# Reporting

## Generation

The report is composed as one self-contained HTML document and rendered to PDF through a bundled
headless browser driven by [Microsoft Playwright](https://playwright.dev/dotnet/).

Generation is entirely offline. Styles are inline, images are embedded as data URIs, and charts are
generated as inline vector graphics, so nothing is fetched at render time. The browser context runs
with JavaScript disabled and offline, and every request is aborted, so a hostile value inside a
directory object could not cause a request to leave the machine even if it escaped escaping.

To point at a browser other than the one a release ships, set `IPA_BROWSER_EXECUTABLE`.

## Sections

Each is individually selectable, and a table of contents is generated from those chosen.

| Section | Contents |
| --- | --- |
| Cover | Branding, customer, assessor, period, versions, sign-off, confidentiality label |
| Scope and methodology | Sources assessed, the read-only statement, how scoring works, accepted exceptions |
| Executive summary | Overall and per-domain scores, severity distribution, operator narrative |
| Scores and coverage | Per-category scores, coverage, status counts, provider metric |
| Prioritised findings | Every finding with observation, risk, remediation, affected objects, mappings |
| Active Directory / Entra / Hybrid detail | Per-domain rule outcomes |
| Baseline comparison | Conformity against the imported Microsoft baseline, and every deviation |
| ISO readiness | Coverage, readiness, status distribution, per-control state |
| Exclusions | Everything not evaluated and why, plus operator annotations |
| Collection diagnostics | The redacted collection log |
| Remediation roadmap | Work ordered by severity then by objects affected, with a horizon |
| Evidence appendix | What was collected, by which collector, when |

## White-label fields

Customer, assessor, assessor company, logo, primary and secondary colour, confidentiality label,
assessment dates, report version, executive narrative, sign-off names, and a product name override
that replaces the product name throughout.

Colours are validated as hexadecimal before reaching a style declaration. Logos are accepted only as
PNG, JPEG, GIF or WebP - vector images are refused because they can carry script.

## Privacy defaults

All three are **off** by default:

| Option | Effect when enabled |
| --- | --- |
| Raw object attributes | Directory and tenant attribute values appear in clear text |
| Full affected-object lists | Every affected object is named rather than a sample of ten |
| Operator attachments | Attachments leave the project boundary with the report |

Each adds its own warning, shown before generation. One warning is always present regardless of the
options: **an exported PDF is not encrypted**, and leaves the encrypted project boundary. Version
one does not encrypt exported reports.

## Layout

Deterministic pagination: sections start on a new page, headings never end one, tables and figures
avoid breaking across pages, and wide table headers repeat on every page they span. Page numbers,
the confidentiality label and a repeated header come from the render templates.

Charts carry a title, a description and a data table with the same numbers, so the report stays
usable when the graphic cannot be seen or the document is read by assistive technology.

## Determinism

The same model always produces byte-identical HTML. The generation instant is supplied by the caller
rather than read from the clock, so a report regenerated from a saved project is identical to the
one saved with it.
