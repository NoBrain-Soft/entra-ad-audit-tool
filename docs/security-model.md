# Security model

## Read-only by construction

"No write requests" is a property of the types, not a convention:

- `LdapDirectoryReader` exposes paged searches and a single-entry read. It has no method that issues
  an add, modify or delete, so a collector cannot write to the directory even by mistake.
- `GraphReadClient` exposes `GetAsync`, `EnumerateAsync` and their non-throwing variants. There is
  no method that issues a `POST`, `PATCH`, `PUT` or `DELETE`.
- Every scope in the permission manifest is read-only. `PermissionManifest.IsReadOnly` compares
  whole dot-separated segments against a verb list, and a test runs it over the entire manifest.

## Directory transport

| Authentication | Permitted transport | Why |
| --- | --- | --- |
| Windows integrated | Signing and sealing, LDAPS, StartTLS | Kerberos transmits no reusable secret |
| Explicit credentials | LDAPS or StartTLS only | A reusable credential must never cross an unprotected channel |

`DirectoryConnectionSettings.Validate` refuses explicit credentials over an unprotected transport
outright. It does not downgrade, and there is no option to override it. The desktop interface
enforces the same rule from both directions so the combination cannot even be selected.

## Certificate validation

A certificate that fails validation is refused unless the operator has recorded a trust exception
that pins **that exact certificate** by SHA-256 thumbprint. Even then:

- A name mismatch is still refused. Pinning attests to the identity of the certificate, not to the
  server being the one the operator intended.
- The exception is recorded with who accepted it, when, and why, and appears in the report's scope
  section.

## Credentials and tokens

Nothing is persisted:

| Secret | Lifetime |
| --- | --- |
| Active Directory password | Held in a `SecureString` for the lifetime of the connection |
| Graph access and refresh tokens | In-process memory only; no token cache is serialised |
| Project passphrase | Derives the container key, then discarded |

The assessment database schema has no column for any of them. The desktop view models clear the
passphrase fields after both the save and the open path, including when the attempt fails.

## Encryption

**Working session.** A SQLCipher database under a random 256-bit key generated in memory at startup.
The key is never written anywhere, so the file is unreadable the moment the process ends. A test
asserts the file on disk does not carry the SQLite header, so encryption at rest is verified rather
than assumed.

**Saved project.** A portable container:

```
magic │ header length │ plaintext header │ manifest ciphertext+tag │ payload ciphertext+tag
```

- AES-256-GCM for both ciphertexts, under **separate subkeys** derived from an Argon2id passphrase
  key, so the manifest and the payload are never encrypted under the same key.
- The plaintext header - format version, Argon2id parameters, nonces - is the **associated data**
  for both ciphertexts, so altering the declared cost parameters is detected.
- The manifest carries a SHA-256 for every payload entry, verified after decryption, so a
  substitution inside a correctly authenticated payload is still caught.
- Argon2id defaults: 64 MiB memory, three passes, parallelism four. Parameters are stored with the
  file rather than assumed, so the cost can be raised in a future release without breaking existing
  projects.

Failure classes are distinguishable, because an operator needs to tell them apart: not a container,
unsupported version, wrong passphrase or tampering, integrity mismatch, and malformed.

## Redaction

`Redaction.Scrub` runs over every diagnostic message and every error surfaced to the operator. It
removes JSON web tokens, bearer headers, refresh tokens, client secrets and password assignments.
`Redaction.IsSensitiveAttribute` covers directory attributes that must never be read into evidence
at all - `unicodePwd`, `ms-Mcs-AdmPwd`, `msLAPS-Password`, `supplementalCredentials` and others - and
the attribute reader consults it before returning any value.

Group Policy Preferences credential detection records the file path, the element and the account
name. It never records the stored value, and a test asserts the value does not appear in the output.

## Hostile input

| Input | Protection |
| --- | --- |
| Baseline package | Entry count, entry size, total size and compression ratio caps; traversal paths refused |
| Project container | Size caps, path escape refused, payload expansion bounded |
| `registry.pol` | File and value size caps; truncated records reported, not thrown |
| Preference XML | Document type declarations prohibited, so external entities never resolve |
| SYSVOL paths | Traversal above the share root refused |
| Object names in reports | Every interpolation escaped; only hexadecimal colours and raster images accepted |
| Report rendering | JavaScript disabled, context offline, every request aborted |

## Telemetry

None. No assessment content leaves the machine. An optional update check may retrieve a signed
release manifest and nothing else; version one installs updates through signed application releases.

The build has its own telemetry to answer for: the interface toolkit reports build-time usage to
its vendor unless `AVALONIA_TELEMETRY_OPTOUT=1` is set. Nothing about an assessment is involved,
but a product that promises to upload nothing should not have its own build reporting to a third
party, so the pipeline sets the variable and a developer building locally should set it too. This
is the only outbound call any part of the repository makes that is not a package restore.
