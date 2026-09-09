#!/usr/bin/env bash
#
# Packages a published Linux build as a .deb and an AppImage.
#
# Usage: build/package-linux.sh <publish-directory> <version>
#
# Both formats wrap the same self-contained publish output, so the application does not depend on a
# .NET runtime being installed on the operator's machine.

set -euo pipefail

PUBLISH_DIR="${1:?A publish directory is required}"
VERSION="${2:?A version is required}"
VERSION="${VERSION#v}"

PACKAGE_NAME="identity-posture-assessor"
BINARY_NAME="IdentityPostureAssessor"
MAINTAINER="NoBrain Software <releases@example.invalid>"
STAGING="$(mktemp -d)"

trap 'rm -rf "$STAGING"' EXIT

if [[ ! -x "$PUBLISH_DIR/$BINARY_NAME" ]]; then
  echo "The publish directory does not contain $BINARY_NAME." >&2
  exit 1
fi

echo "Packaging $PACKAGE_NAME $VERSION from $PUBLISH_DIR"

# ---------------------------------------------------------------------------
# Debian package
# ---------------------------------------------------------------------------

DEB_ROOT="$STAGING/deb"
INSTALL_DIR="$DEB_ROOT/opt/$PACKAGE_NAME"

mkdir -p "$INSTALL_DIR" "$DEB_ROOT/DEBIAN" "$DEB_ROOT/usr/bin" "$DEB_ROOT/usr/share/applications"

cp -r "$PUBLISH_DIR"/. "$INSTALL_DIR/"
chmod 0755 "$INSTALL_DIR/$BINARY_NAME"

ln -s "/opt/$PACKAGE_NAME/$BINARY_NAME" "$DEB_ROOT/usr/bin/$PACKAGE_NAME"

INSTALLED_SIZE="$(du -sk "$INSTALL_DIR" | cut -f1)"

cat > "$DEB_ROOT/DEBIAN/control" <<CONTROL
Package: $PACKAGE_NAME
Version: $VERSION
Section: admin
Priority: optional
Architecture: amd64
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_SIZE
Depends: libx11-6, libice6, libsm6, libfontconfig1, libfreetype6
Description: Identity Posture Assessor
 Read-only posture assessment for one Active Directory forest and one Microsoft
 Entra tenant, with hybrid correlation, ISO/IEC 27001 readiness tracking and
 offline white-label PDF reporting.
CONTROL

# Removing the package leaves saved projects alone: they are the customer's assessment data, and
# the choice to delete them is theirs to make explicitly.
cat > "$DEB_ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

if [ "$1" = "purge" ]; then
  echo "Saved projects were not removed."
  echo "Delete them yourself if they are no longer needed; they hold assessment data."
fi

exit 0
POSTRM

chmod 0755 "$DEB_ROOT/DEBIAN/postrm"

cat > "$DEB_ROOT/usr/share/applications/$PACKAGE_NAME.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Identity Posture Assessor
Comment=Active Directory and Microsoft Entra ID posture assessment
Exec=/usr/bin/$PACKAGE_NAME
Terminal=false
Categories=System;Security;
DESKTOP

dpkg-deb --build --root-owner-group "$DEB_ROOT" \
  "$PUBLISH_DIR/${PACKAGE_NAME}_${VERSION}_amd64.deb"

echo "Wrote ${PACKAGE_NAME}_${VERSION}_amd64.deb"

# ---------------------------------------------------------------------------
# AppImage
# ---------------------------------------------------------------------------

if ! command -v appimagetool >/dev/null 2>&1; then
  echo "appimagetool is not on the path; skipping the AppImage." >&2
  exit 0
fi

APPDIR="$STAGING/AppDir"
mkdir -p "$APPDIR/usr/bin"

cp -r "$PUBLISH_DIR"/. "$APPDIR/usr/bin/"
chmod 0755 "$APPDIR/usr/bin/$BINARY_NAME"

cat > "$APPDIR/AppRun" <<APPRUN
#!/bin/sh
HERE="\$(dirname "\$(readlink -f "\$0")")"
exec "\$HERE/usr/bin/$BINARY_NAME" "\$@"
APPRUN

chmod 0755 "$APPDIR/AppRun"

cat > "$APPDIR/$PACKAGE_NAME.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Identity Posture Assessor
Exec=AppRun
Icon=$PACKAGE_NAME
Terminal=false
Categories=System;Security;
DESKTOP

# A placeholder icon keeps appimagetool happy when no branded icon is supplied.
touch "$APPDIR/$PACKAGE_NAME.png"

ARCH=x86_64 appimagetool "$APPDIR" \
  "$PUBLISH_DIR/${PACKAGE_NAME}-${VERSION}-x86_64.AppImage"

echo "Wrote ${PACKAGE_NAME}-${VERSION}-x86_64.AppImage"
