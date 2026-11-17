#!/bin/sh
set -eu

REPO_URL="${PIXELTUNNEL_REPO_URL:-https://github.com/keenfolk1-lgtm/antigravity-unlocker}"
VERSION="${PIXELTUNNEL_VERSION:-latest}"
INSTALL_DIR="${PIXELTUNNEL_INSTALL_DIR:-$HOME/.local/bin}"
ACTIVATE_KEY=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --activate)
      shift
      if [ "$#" -eq 0 ]; then
        printf "Error: --activate requires a key or URI\n" >&2
        exit 2
      fi
      ACTIVATE_KEY="$1"
      ;;
    --version)
      shift
      if [ "$#" -eq 0 ]; then
        printf "Error: --version requires a tag\n" >&2
        exit 2
      fi
      VERSION="$1"
      ;;
    *)
      printf "Unknown argument: %s\n" "$1" >&2
      exit 2
      ;;
  esac
  shift
done

detect_platform() {
  os_name="$(uname -s)"
  arch_name="$(uname -m)"

  case "$os_name" in
    Darwin)
      os_slug="macos"
      # Handle macOS Apple Silicon running under Rosetta 2 translation
      if [ "$arch_name" = "x86_64" ] && command -v sysctl >/dev/null 2>&1; then
        if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')" = "1" ]; then
          arch_name="arm64"
        fi
      fi
      ;;
    Linux)
      os_slug="linux"
      ;;
    *)
      printf "Unsupported OS: %s\n" "$os_name" >&2
      exit 1
      ;;
  esac

  case "$arch_name" in
    arm64|aarch64)
      arch_slug="arm64"
      ;;
    x86_64|amd64)
      arch_slug="amd64"
      ;;
    *)
      printf "Unsupported CPU architecture: %s\n" "$arch_name" >&2
      exit 1
      ;;
  esac

  ASSET_NAME="pixeltunnel-${os_slug}-${arch_slug}"
  OS_SLUG="$os_slug"
}

download_file() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --connect-timeout 10 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
  else
    printf "Error: curl or wget is required.\n" >&2
    exit 1
  fi
}

compute_sha256() {
  target="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$target" | awk '{print $1}'
  else
    printf "Error: sha256sum or shasum is required for integrity verification.\n" >&2
    exit 1
  fi
}

setup_macos_bundle() {
  bin_path="$1"
  app_dir="$HOME/Applications/PixelTunnel.app"
  macos_dir="$app_dir/Contents/MacOS"
  mkdir -p "$macos_dir"

  cat > "$app_dir/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>PixelTunnel</string>
  <key>CFBundleDisplayName</key>
  <string>PixelTunnel</string>
  <key>CFBundleIdentifier</key>
  <string>space.pixelstore.pixeltunnel</string>
  <key>CFBundleVersion</key>
  <string>2.0.0</string>
  <key>CFBundleShortVersionString</key>
  <string>2.0.0</string>
  <key>CFBundleExecutable</key>
  <string>PixelTunnel</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSUIElement</key>
  <false/>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key>
      <string>PixelTunnel Activation</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>pixeltunnel</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
EOF

  cat > "$macos_dir/PixelTunnel" <<EOF
#!/bin/sh
BIN="$bin_path"
if [ "\$#" -gt 0 ]; then
  case "\$1" in
    pixeltunnel://*)
      exec "\$BIN" activate "\$1"
      ;;
  esac
fi
exec "\$BIN" start
EOF
  chmod 0755 "$macos_dir/PixelTunnel"

  if command -v xattr >/dev/null 2>&1; then
    xattr -dr com.apple.quarantine "$bin_path" "$app_dir" >/dev/null 2>&1 || true
  fi

  lsreg="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  if [ -x "$lsreg" ]; then
    "$lsreg" -f "$app_dir" >/dev/null 2>&1 || true
  fi
}

setup_linux_desktop() {
  bin_path="$1"
  apps_dir="$HOME/.local/share/applications"
  mkdir -p "$apps_dir"

  cat > "$apps_dir/pixeltunnel.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=PixelTunnel
Comment=PixelTunnel v2.0 AI Proxy & Diagnostics 4.0
Exec="$bin_path" activate %u
Terminal=false
Categories=Network;Utility;
MimeType=x-scheme-handler/pixeltunnel;
NoDisplay=false
EOF

  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$apps_dir" >/dev/null 2>&1 || true
  fi
  if command -v xdg-mime >/dev/null 2>&1; then
    xdg-mime default pixeltunnel.desktop x-scheme-handler/pixeltunnel >/dev/null 2>&1 || true
  fi
}

main() {
  detect_platform

  if [ "$VERSION" = "latest" ]; then
    base_url="${REPO_URL}/releases/latest/download"
  else
    base_url="${REPO_URL}/releases/download/${VERSION}"
  fi

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  bin_tmp="${tmp_dir}/${ASSET_NAME}"
  sums_tmp="${tmp_dir}/SHA256SUMS.txt"

  printf "Downloading %s...\n" "$ASSET_NAME"
  download_file "${base_url}/${ASSET_NAME}" "$bin_tmp"
  download_file "${base_url}/SHA256SUMS.txt" "$sums_tmp"

  expected_sha="$(grep " ${ASSET_NAME}\$" "$sums_tmp" | awk '{print $1}' | head -n 1 || true)"
  if [ -z "$expected_sha" ]; then
    expected_sha="$(grep "${ASSET_NAME}" "$sums_tmp" | awk '{print $1}' | head -n 1 || true)"
  fi
  if [ -z "$expected_sha" ]; then
    printf "Error: SHA-256 entry for %s not found in SHA256SUMS.txt\n" "$ASSET_NAME" >&2
    exit 1
  fi

  actual_sha="$(compute_sha256 "$bin_tmp")"
  if [ "$actual_sha" != "$expected_sha" ]; then
    printf "Error: SHA-256 checksum mismatch for %s (expected %s, got %s)\n" "$ASSET_NAME" "$expected_sha" "$actual_sha" >&2
    exit 1
  fi

  mkdir -p "$INSTALL_DIR"
  dest_bin="${INSTALL_DIR}/pixeltunnel"
  mv -f "$bin_tmp" "$dest_bin"
  chmod 0755 "$dest_bin"

  if [ "$OS_SLUG" = "macos" ]; then
    setup_macos_bundle "$dest_bin"
  else
    setup_linux_desktop "$dest_bin"
  fi

  if [ -n "$ACTIVATE_KEY" ]; then
    if ! "$dest_bin" activate "$ACTIVATE_KEY"; then
      printf "Warning: key activation failed; run '%s activate <key>' manually.\n" "$dest_bin" >&2
    fi
  fi

  printf "\nPixelTunnel installed to: %s\n" "$dest_bin"
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      printf "Add %s to your PATH, then run:\n" "$INSTALL_DIR"
      printf "  export PATH=\"%s:\$PATH\"\n" "$INSTALL_DIR"
      ;;
  esac
  printf "Start PixelTunnel:\n  pixeltunnel start\n"
}

main
