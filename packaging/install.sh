#!/usr/bin/env bash
# Tesseract installer. User-scope by default (no root); pass --system for a
# system-wide install (needs sudo, and is only required for the optional
# dm-crypt fast path's polkit helper).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEM=0
[[ "${1:-}" == "--system" ]] && SYSTEM=1

echo "Building release binaries…"
( cd "$REPO_ROOT" && cargo build --release \
    -p tesseract-agent -p tesseract-cli -p tesseract-gui )

TARGET="$REPO_ROOT/target/release"

if [[ $SYSTEM -eq 0 ]]; then
  BIN="$HOME/.local/bin"
  APPS="$HOME/.local/share/applications"
  UNIT="$HOME/.config/systemd/user"
  META="$HOME/.local/share/metainfo"
  mkdir -p "$BIN" "$APPS" "$UNIT" "$META"

  install -m755 "$TARGET/tesseract" "$BIN/tesseract"
  install -m755 "$TARGET/tesseract-agent" "$BIN/tesseract-agent"
  install -m755 "$TARGET/tesseract-gui" "$BIN/tesseract-gui"
  install -m644 "$REPO_ROOT/packaging/com.jegly.tesseract.desktop" "$APPS/"
  install -m644 "$REPO_ROOT/packaging/com.jegly.tesseract.metainfo.xml" "$META/"
  install -m644 "$REPO_ROOT/packaging/tesseract-agent.service" "$UNIT/"
  install -Dm644 "$REPO_ROOT/packaging/icons/hicolor/scalable/apps/com.jegly.tesseract.svg" \
    "$HOME/.local/share/icons/hicolor/scalable/apps/com.jegly.tesseract.svg"
  gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
  install -Dm644 "$REPO_ROOT/tesseract-gui/resources/fonts/DotGothic16-Regular.ttf" \
    "$HOME/.local/share/fonts/DotGothic16-Regular.ttf"
  fc-cache -f "$HOME/.local/share/fonts" 2>/dev/null || true

  # FUSE allow_root is needed for udisks loop-mounting; enable user_allow_other
  if ! grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null; then
    echo "Note: for filesystem auto-mounting, add 'user_allow_other' to /etc/fuse.conf"
    echo "      (otherwise volumes open in file-access mode, still fully functional)."
  fi

  systemctl --user daemon-reload || true
  echo
  echo "Installed to $BIN."
  echo "Start the agent:   systemctl --user enable --now tesseract-agent"
  echo "Or run directly:   tesseract-agent &   then   tesseract-gui"
else
  PREFIX="${PREFIX:-/usr/local}"
  install -Dm755 "$TARGET/tesseract" "$PREFIX/bin/tesseract"
  install -Dm755 "$TARGET/tesseract-agent" "$PREFIX/bin/tesseract-agent"
  install -Dm755 "$TARGET/tesseract-gui" "$PREFIX/bin/tesseract-gui"
  install -Dm644 "$REPO_ROOT/packaging/com.jegly.tesseract.desktop" "$PREFIX/share/applications/com.jegly.tesseract.desktop"
  install -Dm644 "$REPO_ROOT/packaging/com.jegly.tesseract.metainfo.xml" "$PREFIX/share/metainfo/com.jegly.tesseract.metainfo.xml"
  install -Dm644 "$REPO_ROOT/packaging/icons/hicolor/scalable/apps/com.jegly.tesseract.svg" "$PREFIX/share/icons/hicolor/scalable/apps/com.jegly.tesseract.svg"
  install -Dm644 "$REPO_ROOT/packaging/tesseract-agent.service" "$PREFIX/lib/systemd/user/tesseract-agent.service"

  # optional dm-crypt fast path
  if [[ -f "$TARGET/tesseract-mountd" ]]; then
    install -Dm4755 "$TARGET/tesseract-mountd" "/usr/libexec/tesseract-mountd"
    install -Dm644 "$REPO_ROOT/packaging/com.jegly.tesseract.policy" "/usr/share/polkit-1/actions/com.jegly.tesseract.policy"
    setcap cap_sys_admin+ep /usr/libexec/tesseract-mountd || true
  fi
  echo "System install complete under $PREFIX."
fi
