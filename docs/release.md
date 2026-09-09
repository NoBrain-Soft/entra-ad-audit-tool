# Release

## Supported platforms

Officially tested:

- Windows 11 x64
- Ubuntu 24.04 LTS x64
- Debian 13 x64

Other compatible distributions are best-effort. Both targets are supported Avalonia desktop
platforms; see [Avalonia platforms](https://docs.avaloniaui.net/docs/supported-platforms).

## Runtime

.NET 10, a long-term support release supported through November 2028; see the
[.NET lifecycle](https://learn.microsoft.com/en-us/dotnet/core/releases-and-support). Releases are
published self-contained, so no runtime installation is required on the operator's machine.

## Building a release

```bash
# Windows
dotnet publish src/Ipa.Desktop -c Release -r win-x64 --self-contained \
  -p:PublishSingleFile=true -o artifacts/win-x64

# Linux
dotnet publish src/Ipa.Desktop -c Release -r linux-x64 --self-contained \
  -o artifacts/linux-x64
```

The browser component used for report rendering ships with the release. Point
`IPA_BROWSER_EXECUTABLE` at it if it is not where the library would look.

## Signing

| Target | Requirement |
| --- | --- |
| Windows installers and binaries | Authenticode, using the organisation's code-signing certificate |
| Linux packages | Detached signature over the package, plus a signed checksum file |

Signing keys live in the release pipeline's secret store and never in this repository.

## Linux packaging

Version one publishes `.deb` and AppImage. Each release carries:

- Signed SHA-256 checksums for every artefact
- A software bill of materials in SPDX or CycloneDX form
- Third-party notices, generated from the restored package graph
- Reproducible release metadata: commit, build timestamp, .NET SDK version, rule-pack version

Deterministic build settings are enabled solution-wide, and `ContinuousIntegrationBuild` is set when
`CI` is set, so paths are normalised in the produced assemblies.

## Uninstall

The uninstaller offers a **separate, explicit choice** about deleting saved projects. Projects are
the customer's assessment data, so removing the application never removes them silently.

Ephemeral session directories are removed on a normal exit. Any left by a crash are detected at the
next start and offered for deletion.

## Updates

Version one installs updates through signed application releases. An optional update check may
retrieve a signed release manifest and nothing else. No assessment content is uploaded, ever.

## Licensing and entitlement

Commercial distribution in version one carries no online licence enforcement. Entitlement and
activation can be added later without any access to assessment data, because assessment data never
leaves the operator's machine.
