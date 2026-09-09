# Build and packaging

| Script | Purpose |
| --- | --- |
| `package-linux.sh` | Wraps a self-contained Linux publish as a `.deb` and an AppImage |
| `sign-windows.ps1` | Signs published Windows binaries with Authenticode and verifies each signature |

Both are driven by [`release.yml`](../.github/workflows/release.yml). Signing runs only where the
release secrets are configured, so a fork build still completes.

Removing the Debian package deliberately leaves saved projects in place and says so: they hold the
customer's assessment data, and deleting them is a choice the operator makes explicitly.
