#!/usr/bin/env bash
# Install or check the developer's dagu CLI and the shared txe-dagu-jobs skill
# on this machine, for every Claude Code and Codex profile (TXE-4708).
#
#   txe/developer/install.sh --tag txe-v2.18.2-12                  # build that fork tag
#   txe/developer/install.sh --tag txe-v2.18.2-11 --binary /abs/dagu-2.18.2-txe.11
#                                                                 # install an accepted build of it
#   txe/developer/install.sh --check                              # read back; changes nothing
#
# What it does:
#
#   1. The binary goes to $TXE_DAGU_CLI_ROOT/bin/dagu-<version>. Earlier versions
#      are kept; a different file already at that name is refused.
#   2. $TXE_DAGU_CLI_ROOT/bin/dagu is a small wrapper around it. For `dagu txe ...`
#      it names the developer's own context store, under
#      $TXE_DAGU_CLI_ROOT/client/data, so `dagu txe login --hub` keeps the
#      developer's sign-in there and never in the machine's own store, which
#      belongs to this machine's worker. The TXE home (machine identity,
#      packages, receipts, skill) is the machine's and is shared.
#   3. $TXE_DAGU_LINK_DIR/dagu (default ~/.local/bin/dagu) links to the wrapper.
#      It replaces only a link it can name: its own, or the worker installer's
#      link to $TXE_DAGU_HOME/bin/dagu. The worker keeps that binary and runs
#      its jobs with it; nothing of the worker's is changed.
#   4. The skill this binary carries is unpacked under the TXE home
#      (dagu txe skill install), and every profile gets a link to it:
#        ~/.coding_skills/txe-dagu-jobs   -> the unpacked skill, when ~/.coding_skills exists
#        <profile>/skills/txe-dagu-jobs   -> ~/.coding_skills/txe-dagu-jobs, or else the unpacked skill
#      for every ~/.claude*, ~/.codex* and $CODEX_HOME that exists, and
#      ~/.agents/skills, which Codex also reads. An entry already there that
#      is not such a link (a real directory, or a link elsewhere) is someone's:
#      it is reported and kept.
#   5. It reads everything back: the version `dagu` on PATH runs, the wrapper,
#      and the skill revision every location resolves to. Any location not on
#      this binary's revision fails the run.
#
# No credential is read, copied or written. Signing in is the developer's own
# step afterwards: dagu txe login --hub https://<the hub's address>
set -euo pipefail

TXE_DAGU_HOME="${TXE_DAGU_HOME:-$HOME/.local/share/txe-dagu}"
TXE_DAGU_CLI_ROOT="${TXE_DAGU_CLI_ROOT:-$HOME/.local/share/txe-dagu-cli}"
TXE_DAGU_LINK_DIR="${TXE_DAGU_LINK_DIR:-$HOME/.local/bin}"
TXE_DAGU_REPO="${TXE_DAGU_REPO:-https://github.com/txehq/dagu.git}"
CODING_SKILLS="${CODING_SKILLS:-$HOME/.coding_skills}"
SKILL=txe-dagu-jobs

die() { printf 'txe-dagu-cli: %s\n' "$*" >&2; exit 1; }
say() { printf '%-8s %s\n' "$1" "$2"; }
sum256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -c1-16; }

tag="" binary="" check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --binary) binary="${2:-}"; shift 2 ;;
    --check) check=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

wrapper="$TXE_DAGU_CLI_ROOT/bin/dagu"
link="$TXE_DAGU_LINK_DIR/dagu"
unpacked="$TXE_DAGU_HOME/skill/current"

# make_link creates exactly this pathname as a link to target, or reports why
# not. An existing file, link or directory there is never written into or
# replaced (ln -s would put the link inside a directory).
make_link() {
  python3 -I -c '
import os, sys
try:
    os.symlink(sys.argv[1], sys.argv[2])
    print("made")
except FileExistsError:
    print("exists")
except OSError as e:
    print("failed: %s" % e.strerror)' "$1" "$2"
}

# same_place says whether two paths resolve to the same directory.
same_place() {
  local a b
  a="$(cd "$1" 2>/dev/null && pwd -P)" || return 1
  b="$(cd "$2" 2>/dev/null && pwd -P)" || return 1
  [ "$a" = "$b" ]
}

# The profile skills directories on this machine: each Claude and Codex home
# that exists, and the user-level directory Codex reads.
profiles() {
  local d
  {
    for d in "$HOME"/.claude "$HOME"/.claude[0-9]* "$HOME"/.codex "$HOME"/.codex[0-9]* ${CODEX_HOME:+"$CODEX_HOME"}; do
      [ -d "$d" ] && [ ! -L "$d" ] && printf '%s\n' "$d/skills"
    done
    if [ -d "$HOME/.agents" ] || [ -d "$HOME/.codex" ] || command -v codex >/dev/null 2>&1; then
      printf '%s\n' "$HOME/.agents/skills"
    fi
  } | awk '!seen[$0]++'
}

# place_skill gives a skills directory its link to target, unless something
# that is not such a link is already there.
place_skill() {
  local dir="$1" target="$2" entry="$1/$SKILL" made
  if [ -L "$entry" ] && same_place "$entry" "$target"; then
    say skill "$entry"
    return
  fi
  if [ -e "$entry" ] || [ -L "$entry" ]; then
    say kept "$entry is not a link to this skill; left as it is"
    return
  fi
  mkdir -p "$dir"
  made="$(make_link "$target" "$entry")"
  case "$made" in
    made) say skill "$entry -> $target" ;;
    *) say kept "$entry: $made" ;;
  esac
}

if [ "$check" = 0 ]; then
  [[ "$tag" =~ ^txe-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]] || die "--tag must be txe-v<major>.<minor>.<patch>-<n>"
  version="${BASH_REMATCH[1]}-txe.${BASH_REMATCH[2]}"
  bin="$TXE_DAGU_CLI_ROOT/bin/dagu-$version"
  umask 022

  # 1. The binary: an accepted build given with --binary, or built from the tag.
  if [ -n "$binary" ]; then
    [ -f "$binary" ] && [ -x "$binary" ] || die "--binary $binary is not an executable file"
    built="$binary"
  else
    command -v go >/dev/null || die "go is not on PATH"
    src="$(mktemp -d)"
    trap 'rm -rf "$src"' EXIT
    git clone --quiet --depth 1 --branch "$tag" "$TXE_DAGU_REPO" "$src/dagu"
    (cd "$src/dagu" && GOTOOLCHAIN=auto go build -ldflags "-X 'main.version=$version'" -o "$src/dagu.bin" ./cmd)
    built="$src/dagu.bin"
  fi
  got="$("$built" version 2>/dev/null | head -1)"
  [ "$got" = "$version" ] || die "the binary says it is version '$got', not $version ($tag)"
  mkdir -p "$TXE_DAGU_CLI_ROOT/bin"
  # The developer's context store: its key and sign-in context are this user's only.
  mkdir -p "$TXE_DAGU_CLI_ROOT/client/data" && chmod 0700 "$TXE_DAGU_CLI_ROOT/client" "$TXE_DAGU_CLI_ROOT/client/data"
  if [ -e "$bin" ]; then
    cmp -s "$built" "$bin" || die "$bin already exists and differs from this build; move it away first"
  else
    cp "$built" "$bin.tmp" && chmod 0755 "$bin.tmp" && mv "$bin.tmp" "$bin"
  fi
  say binary "$bin (sha256 $(sum256 "$bin"))"

  # 2. The wrapper, replaced as a whole.
  cat > "$wrapper.tmp" <<EOF
#!/bin/sh
# Written by txe/developer/install.sh ($tag). dagu txe commands use the
# developer's own context store; the machine's worker keeps its own.
binary='$bin'
store='$TXE_DAGU_CLI_ROOT/client/data'
if [ "\${1-}" = txe ]; then
    shift
    exec "\$binary" txe --contexts-dir "\$store/contexts" --data-dir "\$store" "\$@"
fi
exec "\$binary" "\$@"
EOF
  chmod 0755 "$wrapper.tmp" && mv "$wrapper.tmp" "$wrapper"
  say wrapper "$wrapper"

  # 3. dagu on PATH.
  worker_link="$TXE_DAGU_HOME/bin/dagu"
  if [ -L "$link" ] && { [ "$(readlink "$link")" = "$wrapper" ] || [ "$(readlink "$link")" = "$worker_link" ]; }; then
    ln -sfn "$wrapper" "$link.tmp" && mv -f "$link.tmp" "$link"
    say path "$link -> $wrapper"
  else
    mkdir -p "$TXE_DAGU_LINK_DIR"
    made="$(make_link "$wrapper" "$link")"
    case "$made" in
      made) say path "$link -> $wrapper" ;;
      exists) say path "not linked: $link is not this install's link nor the worker's; it is left as it is" ;;
      *) say path "not linked: $link: $made" ;;
    esac
  fi

  # 4. The skill, then a link in every profile.
  "$wrapper" txe skill install >/dev/null
  if [ -d "$CODING_SKILLS" ]; then
    place_skill "$CODING_SKILLS" "$unpacked"
    profile_target="$CODING_SKILLS/$SKILL"
  else
    profile_target="$unpacked"
  fi
  while IFS= read -r dir; do
    place_skill "$dir" "$profile_target"
  done < <(profiles)
fi

# 5. Read back.
failed=0
on_path="$(command -v dagu || true)"
if [ -n "$on_path" ] && same_place "$(dirname "$on_path")" "$TXE_DAGU_LINK_DIR" && [ "$(readlink "$on_path" 2>/dev/null)" = "$wrapper" ]; then
  say path "dagu -> $wrapper, version $(dagu version 2>/dev/null | head -1)"
else
  say path "dagu on PATH is ${on_path:-missing}, not $link -> $wrapper"
  failed=1
fi
[ -x "$wrapper" ] || { say wrapper "missing: $wrapper"; failed=1; }
links=()
[ -d "$CODING_SKILLS" ] && links+=(--link "$CODING_SKILLS")
while IFS= read -r dir; do links+=(--link "$dir"); done < <(profiles)
if ! "$wrapper" txe skill status "${links[@]}"; then
  failed=1
fi
[ "$failed" = 0 ] || die "not every part is in place; see above"
echo "ok. Sign in with: dagu txe login --hub https://<the hub's address>"
