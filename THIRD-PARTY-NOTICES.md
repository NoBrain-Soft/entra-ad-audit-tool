# Third-party notices

This product uses the following third-party components. Full licence texts are generated into each
release's notices file from the restored package graph; this list records what is used and why.

| Component | Purpose | Licence |
| --- | --- | --- |
| Avalonia | Cross-platform desktop user interface | MIT |
| CommunityToolkit.Mvvm | View model infrastructure | MIT |
| Microsoft.Identity.Client (MSAL) | Public-client authentication to Microsoft Entra | MIT |
| System.DirectoryServices.Protocols | LDAP client | MIT |
| SMBLibrary | Managed SMB2 client for SYSVOL | LGPL-3.0 |
| Microsoft.Data.Sqlite.Core | Database access | MIT |
| SQLitePCLRaw.bundle_e_sqlcipher | SQLCipher-backed SQLite provider | Apache-2.0 |
| SQLCipher (via the bundle above) | Encryption of the working session database | BSD-3-Clause |
| Konscious.Security.Cryptography.Argon2 | Argon2id passphrase key derivation | MIT |
| Microsoft.Playwright | Headless browser automation for PDF rendering | Apache-2.0 |
| Chromium (bundled with Playwright) | PDF rendering engine | BSD-3-Clause and others |
| xunit | Test framework | Apache-2.0 |

`SMBLibrary` is used under the LGPL. It is consumed as an unmodified binary package and is
dynamically linked, and the release includes the notice and a pointer to the upstream source.

## Material this product does not redistribute

**Microsoft security baselines.** The operator supplies a Security Compliance Toolkit package they
already hold. The product parses it, records its identity and hashes, and compares against it. It
never ships a baseline package.
See [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319).

**ISO/IEC 27001 text.** The standard is copyright protected. The product ships control identifiers
together with labels and guidance written by this product. An operator with a licence may record the
official wording inside their own project, where it stays.
See [ISO/IEC 27001:2022](https://www.iso.org/standard/27001).
