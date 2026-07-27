#!/usr/bin/env bash
set -euo pipefail

toolchain="${1:-nightly-2026-07-08}"
required_components=(
  "rustc-dev"
  "rust-src"
  "llvm-tools-preview"
  "rustfmt"
  "clippy"
)

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

installed_components() {
  local component_host
  component_host="$(rustc +"$toolchain" -vV 2>/dev/null | awk '/^host: / {print $2}')"
  rustup component list --toolchain "$toolchain" --installed \
    | while IFS= read -r line; do
      local component="${line%% *}"
      if [[ -n "$component_host" && "$component" == *-"$component_host" ]]; then
        component="${component%-"$component_host"}"
      fi
      if [[ "$component" == "llvm-tools" ]]; then
        component="llvm-tools-preview"
      fi
      printf '%s\n' "$component"
    done
}

status="pass"
message=""
missing=()

if ! rustc_version="$(rustc +"$toolchain" --version --verbose 2>&1)"; then
  status="fail"
  message="$rustc_version"
else
  installed="$(installed_components || true)"
  for component in "${required_components[@]}"; do
    if ! grep -qx "$component" <<<"$installed"; then
      missing+=("$component")
    fi
  done

  if ((${#missing[@]} > 0)); then
    status="fail"
    message="missing components: ${missing[*]}"
  else
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT
    cat >"$tmpdir/check.rs" <<'RS'
#![feature(rustc_private)]
extern crate rustc_driver;

fn main() {
    let _ = std::any::type_name::<rustc_driver::Callbacks>();
}
RS
    if ! compile_output="$(RUSTC_BOOTSTRAP=1 rustc +"$toolchain" "$tmpdir/check.rs" -o "$tmpdir/check" 2>&1)"; then
      status="fail"
      message="$compile_output"
    fi
  fi
fi

host="$(rustc +"$toolchain" -vV 2>/dev/null | awk '/^host: / {print $2}')"
commit="$(rustc +"$toolchain" -vV 2>/dev/null | awk '/^commit-hash: / {print $2}')"
installed_json="$(installed_components 2>/dev/null | awk 'BEGIN {printf "["} {if (NR>1) printf ","; printf "\"%s\"", $0} END {printf "]"}')"

printf '{'
printf '"toolchain":"%s",' "$(json_escape "$toolchain")"
printf '"rustc_commit":"%s",' "$(json_escape "${commit:-unknown}")"
printf '"host":"%s",' "$(json_escape "${host:-unknown}")"
printf '"components":%s,' "${installed_json:-[]}"
printf '"result":"%s",' "$(json_escape "$status")"
printf '"message":"%s"' "$(json_escape "$message")"
printf '}\n'

if [[ "$status" != "pass" ]]; then
  exit 1
fi
