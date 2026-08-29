#!/usr/bin/env bash
# Cross-compile zsync release zips for macOS / Linux / Windows.
#
# Linker choice:
#   target OS == host OS  → cargo (native SDK / libc)
#     Darwin also cross-arch (x64 ↔ arm64) with the Apple SDK
#     Linux/Windows different arch → zigbuild
#   target OS != host OS  → cargo zigbuild
#     Linux glibc 2.17; Windows gnu; macOS only if SDKROOT is set
#
# Path scrub: isolated CARGO_HOME / CARGO_TARGET_DIR, remap-path-prefix,
# -C strip=symbols, then a post-link strip. strings scan fails on leftover
# personal paths.
#
# Env: CARGO_HOME_DIR, CARGO_TARGET_DIR, DIST_DIR, ZSYNC_LINUX_GLIBC
#      SKIP_PACKAGE=1  SKIP_VERIFY=1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NAME="zsync"
DIST_DIR="${DIST_DIR:-dist}"
GLIBC="${ZSYNC_LINUX_GLIBC:-2.17}"
CARGO_HOME_DIR="${CARGO_HOME_DIR:-/tmp/zsync-cargo}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/zsync-target}"
RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"

VERSION="$(cargo metadata --no-deps --format-version 1 2>/dev/null \
  | sed -n 's/.*"name":"zsync","version":"\([^"]*\)".*/\1/p' | head -n1)"
if [[ -z "${VERSION}" ]]; then
  VERSION="$(grep -E '^version\s*=' Cargo.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
fi

HOST_UNAME="$(uname -s)"
HOST_TRIPLE="$(rustc -vV | awk '/^host:/{print $2}')"

case "${HOST_UNAME}" in
  Darwin) HOST_KIND="macos" ;;
  Linux) HOST_KIND="linux" ;;
  MINGW*|MSYS*|CYGWIN*) HOST_KIND="windows" ;;
  *) HOST_KIND="unknown" ;;
esac

host_arch_name() {
  case "${HOST_TRIPLE}" in
    x86_64-*) echo x64 ;;
    aarch64-*) echo arm64 ;;
    *) echo unknown ;;
  esac
}

os_of_triple() {
  case "$1" in
    *apple-darwin*) echo macos ;;
    *linux*) echo linux ;;
    *windows*) echo windows ;;
    *) echo unknown ;;
  esac
}

arch_of_triple() {
  case "$1" in
    x86_64-*) echo x64 ;;
    aarch64-*) echo arm64 ;;
    *) echo unknown ;;
  esac
}

HOST_ARCH_NAME="$(host_arch_name)"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: missing required command: $1" >&2
    [[ -n "${2:-}" ]] && echo "  hint: $2" >&2
    exit 1
  }
}

ensure_target() {
  local triple="$1"
  if ! rustc --print target-list | grep -qx "${triple}"; then
    echo "error: rustc has no built-in target ${triple}" >&2
    return 1
  fi
  if ! rustup target list --installed | grep -qx "${triple}"; then
    echo "==> rustup target add ${triple}"
    rustup target add "${triple}"
  fi
}

# rustc last-match-wins for overlapping remaps: list broad prefixes first.
build_remap_flags() {
  local flags=()
  flags+=("--remap-path-prefix=${HOME}=/home")
  if [[ -n "${RUSTUP_HOME}" && -d "${RUSTUP_HOME}" ]]; then
    flags+=("--remap-path-prefix=${RUSTUP_HOME}=/rustup")
  fi
  flags+=("--remap-path-prefix=${CARGO_HOME_DIR}=/cargo")
  flags+=("--remap-path-prefix=${ROOT}=/src")
  flags+=("--remap-path-prefix=${CARGO_TARGET_DIR}=/target")
  flags+=("-C" "strip=symbols")
  local out="" f
  for f in "${flags[@]}"; do
    out+="${out:+ }${f}"
  done
  printf '%s' "$out"
}

export_build_env() {
  local extra="${1:-}"
  mkdir -p "$CARGO_HOME_DIR" "$CARGO_TARGET_DIR"
  export CARGO_HOME="$CARGO_HOME_DIR"
  export CARGO_TARGET_DIR
  local remap
  remap="$(build_remap_flags)"
  if [[ -n "$extra" ]]; then
    export RUSTFLAGS="${remap} ${extra}"
  else
    export RUSTFLAGS="${remap}"
  fi
}

use_native() {
  local triple="$1"
  local tos tarch
  tos="$(os_of_triple "${triple}")"
  tarch="$(arch_of_triple "${triple}")"
  if [[ "${tos}" != "${HOST_KIND}" ]]; then
    return 1
  fi
  # Same OS: Darwin can native-cross x64/arm64; other OSes only same arch.
  if [[ "${HOST_KIND}" == "macos" ]]; then
    return 0
  fi
  [[ "${tarch}" == "${HOST_ARCH_NAME}" ]]
}

bin_path() {
  local triple="$1"
  local bin="${CARGO_TARGET_DIR}/${triple}/release/${NAME}"
  if [[ "${triple}" == *"-windows-"* ]]; then
    bin="${bin}.exe"
  fi
  printf '%s' "$bin"
}

package_zip() {
  local os_name="$1"
  local arch_name="$2"
  local src_bin="$3"
  local zip_name="${NAME}-${os_name}-${arch_name}-${VERSION}.zip"
  local stage="${DIST_DIR}/.stage-${os_name}-${arch_name}"
  local bin_name="${NAME}"
  if [[ "${os_name}" == "windows" ]]; then
    bin_name="${NAME}.exe"
  fi

  rm -rf "${stage}"
  mkdir -p "${stage}" "${DIST_DIR}"
  cp "${src_bin}" "${stage}/${bin_name}"

  rm -f "${DIST_DIR}/${zip_name}"
  (
    cd "${stage}"
    zip -qr "${ROOT}/${DIST_DIR}/${zip_name}" "${bin_name}"
  )
  rm -rf "${stage}"
  echo "    -> ${DIST_DIR}/${zip_name}"
}

find_rust_objcopy() {
  local sysroot
  sysroot="$(rustc --print sysroot 2>/dev/null)" || return 0
  find "${sysroot}/lib/rustlib" -name rust-objcopy -type f 2>/dev/null | head -1
}

strip_bin() {
  local triple="$1"
  local bin="$2"
  local tos
  tos="$(os_of_triple "${triple}")"
  echo "==> strip ${tos} $(basename "$bin")"
  case "${tos}" in
    macos)
      if command -v strip >/dev/null 2>&1 && strip -x "$bin" 2>/dev/null; then
        return 0
      fi
      if command -v llvm-strip >/dev/null 2>&1; then
        llvm-strip "$bin" && return 0
      fi
      echo "warn: macOS strip skipped for $bin (already stripped?)" >&2
      ;;
    linux)
      local objcopy
      objcopy="$(find_rust_objcopy)"
      if [[ -n "${objcopy}" ]]; then
        "$objcopy" --strip-all "$bin"
        return 0
      fi
      if command -v llvm-strip >/dev/null 2>&1; then
        llvm-strip --strip-all "$bin"
        return 0
      fi
      echo "warn: no rust-objcopy/llvm-strip; relying on -C strip=symbols for $bin" >&2
      ;;
    windows)
      if command -v x86_64-w64-mingw32-strip >/dev/null 2>&1; then
        x86_64-w64-mingw32-strip "$bin" || echo "warn: mingw strip failed for $bin" >&2
        return 0
      fi
      local objcopy
      objcopy="$(find_rust_objcopy)"
      if [[ -n "${objcopy}" ]]; then
        "$objcopy" --strip-all "$bin" || echo "warn: rust-objcopy strip failed for $bin" >&2
        return 0
      fi
      echo "warn: no Windows strip tool; relying on -C strip=symbols for $bin" >&2
      ;;
  esac
}

verify_no_personal_paths() {
  local bin="$1"
  local label="$2"
  if ! command -v strings >/dev/null 2>&1; then
    echo "warn: strings not found; skip path scan for $label" >&2
    return 0
  fi
  echo "==> verify paths: $label"
  local hits
  hits="$(
    strings "$bin" | grep -E \
      -e "${HOME}" \
      -e "${CARGO_HOME_DIR}" \
      -e "${CARGO_TARGET_DIR}" \
      -e "${ROOT}" \
      -e '/Users/[^/]+/\.cargo' \
      -e '/Users/[^/]+/\.rustup' \
      -e '/Users/[^/]+/Dev/' \
      || true
  )"
  if [[ -n "$hits" ]]; then
    echo "error: personal path(s) still embedded in $bin:" >&2
    echo "$hits" | head -40 >&2
    return 1
  fi
  echo "    OK: $bin"
}

# Prints the binary path on success.
build_one() {
  local triple="$1"
  local os_name="$2"
  local arch_name="$3"
  local bin extra=""

  ensure_target "${triple}" || return 1

  if use_native "${triple}"; then
    echo "==> native cargo --release --target ${triple}"
    export_build_env
    cargo build --release --target "${triple}" || return 1
  else
    local zig_target="${triple}"
    if [[ "${os_name}" == "linux" ]]; then
      zig_target="${triple}.${GLIBC}"
    fi
    if [[ "${os_name}" == "macos" && -z "${SDKROOT:-}" && "${HOST_KIND}" != "macos" ]]; then
      echo "warning: SDKROOT unset; skipping ${os_name}-${arch_name}" >&2
      return 1
    fi
    extra=""
    if [[ "${os_name}" == "windows" && -n "${MINGW_DLLTOOL:-}" ]] \
      && command -v "${MINGW_DLLTOOL}" >/dev/null 2>&1; then
      extra="-C dlltool=${MINGW_DLLTOOL}"
      export "CC_x86_64_pc_windows_gnu=${MINGW_CC:-x86_64-w64-mingw32-gcc}"
      export "AR_x86_64_pc_windows_gnu=${MINGW_AR:-x86_64-w64-mingw32-ar}"
    fi
    echo "==> cargo zigbuild --release --target ${zig_target}"
    export_build_env "${extra}"
    cargo zigbuild --release --target "${zig_target}" || return 1
  fi

  bin="$(bin_path "${triple}")"
  if [[ ! -f "${bin}" ]]; then
    echo "error: missing binary ${bin}" >&2
    return 1
  fi
  strip_bin "${triple}" "${bin}"
  if [[ "${SKIP_VERIFY:-0}" != "1" ]]; then
    verify_no_personal_paths "${bin}" "${os_name}-${arch_name}"
  fi
  if [[ "${SKIP_PACKAGE:-0}" != "1" ]]; then
    package_zip "${os_name}" "${arch_name}" "${bin}"
  fi
}

try_build() {
  if ! build_one "$@"; then
    echo "warning: skipped $2-$3" >&2
    return 0
  fi
}

echo "${NAME} ${VERSION} → ${DIST_DIR}/ (host ${HOST_KIND}/${HOST_ARCH_NAME} ${HOST_TRIPLE}, linux glibc ${GLIBC})"
echo "native cargo on ${HOST_KIND}; zigbuild for other OSes"
echo "zip: ${NAME}-{os}-{arch}-{version}.zip"

need_cmd cargo "rustup default stable"
need_cmd rustup "https://rustup.rs/"
need_cmd zig "mise release installs zig via task tools"
need_cmd cargo-zigbuild "mise release installs cargo-zigbuild via task tools"
need_cmd zip

echo "==> clean cargo target cache ${CARGO_TARGET_DIR}"
rm -rf "${CARGO_TARGET_DIR}"

export_build_env
if ! cargo fetch -q; then
  echo "repairing broken registry in $CARGO_HOME_DIR" >&2
  rm -rf "$CARGO_HOME_DIR/registry"
  cargo fetch -q
fi

mkdir -p "${DIST_DIR}"

# --- Linux ---
try_build "x86_64-unknown-linux-gnu" "linux" "x64"
try_build "aarch64-unknown-linux-gnu" "linux" "arm64"

# --- Windows ---
if [[ "${HOST_KIND}" == "windows" ]]; then
  build_one "${HOST_TRIPLE}" "windows" "${HOST_ARCH_NAME}"
else
  build_one "x86_64-pc-windows-gnu" "windows" "x64"
fi

# --- macOS ---
if [[ "${HOST_KIND}" == "macos" ]]; then
  try_build "x86_64-apple-darwin" "macos" "x64"
  try_build "aarch64-apple-darwin" "macos" "arm64"
  if command -v lipo >/dev/null 2>&1 \
    && [[ -f "$(bin_path x86_64-apple-darwin)" ]] \
    && [[ -f "$(bin_path aarch64-apple-darwin)" ]]; then
    echo "==> lipo macos-universal"
    univ_bin="${DIST_DIR}/.zsync-universal"
    lipo -create \
      -output "${univ_bin}" \
      "$(bin_path x86_64-apple-darwin)" \
      "$(bin_path aarch64-apple-darwin)"
    strip_bin "aarch64-apple-darwin" "${univ_bin}"
    if [[ "${SKIP_PACKAGE:-0}" != "1" ]]; then
      package_zip "macos" "universal" "${univ_bin}"
    fi
    rm -f "${univ_bin}"
  fi
else
  echo "note: host is not macOS; Apple targets need a macOS SDK (SDKROOT)"
  try_build "x86_64-apple-darwin" "macos" "x64"
  try_build "aarch64-apple-darwin" "macos" "arm64"
fi

rm -rf "${DIST_DIR}"/.stage-* 2>/dev/null || true

echo
echo "Done. Artifacts:"
ls -la "${DIST_DIR}"/${NAME}-*-*.zip 2>/dev/null | sed 's/^/  /' || ls -la "${DIST_DIR}" | sed 's/^/  /'
