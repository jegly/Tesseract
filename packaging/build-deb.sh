#!/usr/bin/env bash
# Build a .deb package for Tesseract.
# Run from anywhere; output is tesseract_<version>_amd64.deb at the repo root.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(grep '^version' "$REPO/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
ARCH="$(dpkg --print-architecture)"
PKG="tesseract_${VERSION}_${ARCH}"
STAGING="$REPO/target/deb-staging/$PKG"

echo "==> Building release binaries…"
cd "$REPO"
cargo build --release -p tesseract-agent -p tesseract-cli -p tesseract-gui
REL="$REPO/target/release"

echo "==> Assembling package tree at $STAGING…"
rm -rf "$STAGING"
install -d \
  "$STAGING/DEBIAN" \
  "$STAGING/usr/bin" \
  "$STAGING/usr/lib/systemd/user" \
  "$STAGING/usr/share/applications" \
  "$STAGING/usr/share/metainfo" \
  "$STAGING/usr/share/icons/hicolor/scalable/apps" \
  "$STAGING/usr/share/fonts/truetype/tesseract" \
  "$STAGING/usr/share/polkit-1/actions"

# Binaries
install -m755 "$REL/tesseract"       "$STAGING/usr/bin/tesseract"
install -m755 "$REL/tesseract-agent" "$STAGING/usr/bin/tesseract-agent"
install -m755 "$REL/tesseract-gui"   "$STAGING/usr/bin/tesseract-gui"

# Desktop integration
install -m644 "$REPO/packaging/com.jegly.tesseract.desktop"      "$STAGING/usr/share/applications/"
install -m644 "$REPO/packaging/com.jegly.tesseract.metainfo.xml" "$STAGING/usr/share/metainfo/"
install -m644 "$REPO/packaging/com.jegly.tesseract.svg"          "$STAGING/usr/share/icons/hicolor/scalable/apps/"
install -m644 "$REPO/packaging/com.jegly.tesseract.policy"       "$STAGING/usr/share/polkit-1/actions/"
sed 's|ExecStart=.*tesseract-agent|ExecStart=/usr/bin/tesseract-agent|' \
  "$REPO/packaging/tesseract-agent.service" \
  > "$STAGING/usr/lib/systemd/user/tesseract-agent.service"
chmod 644 "$STAGING/usr/lib/systemd/user/tesseract-agent.service"

# Font
install -m644 "$REPO/tesseract-gui/resources/fonts/DotGothic16-Regular.ttf" \
  "$STAGING/usr/share/fonts/truetype/tesseract/"

# DEBIAN/control
cat > "$STAGING/DEBIAN/control" <<EOF
Package: tesseract
Version: $VERSION
Architecture: $ARCH
Maintainer: jegly <jjjegly@gmail.com>
Depends: libgtk-4-1 (>= 4.10), libadwaita-1-0 (>= 1.4), udisks2, fuse3
Section: utils
Priority: optional
Homepage: https://github.com/jegly/Tesseract
Description: Multi-cipher cascade encryption with post-quantum key wrapping
 Privilege-separated, post-quantum disk and file encryption for the Linux
 desktop. Stack AES, Serpent, Twofish, ChaCha20 and more in any order you
 choose. A sandboxed key agent owns all key material; the GTK4 GUI and CLI
 never touch a key. Runs entirely without root.
EOF

# DEBIAN/postinst — reload user units and update caches
cat > "$STAGING/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    systemctl --user daemon-reload 2>/dev/null || true
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
    fc-cache -f /usr/share/fonts/truetype/tesseract 2>/dev/null || true
fi
EOF
chmod 755 "$STAGING/DEBIAN/postinst"

# DEBIAN/postrm — clean up caches on remove
cat > "$STAGING/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
    fc-cache -f 2>/dev/null || true
fi
EOF
chmod 755 "$STAGING/DEBIAN/postrm"

echo "==> Building .deb…"
dpkg-deb --build --root-owner-group "$STAGING" "$REPO/${PKG}.deb"

echo ""
echo "Done: $REPO/${PKG}.deb"
echo "Install with:  sudo dpkg -i ${PKG}.deb"
echo "               sudo apt-get install -f   # if deps are missing"
