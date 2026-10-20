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
#      are kept; a different file already at that name is refused. A build from
#      the tag is reproducible (-trimpath), so building the same tag again with
#      the same toolchain gives the same file.
#   2. $TXE_DAGU_CLI_ROOT/bin/dagu is a small wrapper around it. For a dagu txe
#      command, with or without --context before it, it names the developer's
#      own context store, under $TXE_DAGU_CLI_ROOT/client/data, so
#      `dagu txe login --hub` keeps the developer's sign-in there and never in
#      the machine's own store, which belongs to this machine's worker. The TXE
#      home (machine identity, packages, receipts, skill) is the machine's and
#      is shared.
#   3. $TXE_DAGU_LINK_DIR/dagu (default ~/.local/bin/dagu) links to the wrapper.
#      It replaces only a link it can name: its own, or the worker installer's
#      link to $TXE_DAGU_HOME/bin/dagu. The worker keeps that binary and runs
#      its jobs with it; nothing of the worker's is changed.
#   4. The skill this binary carries is unpacked under the TXE home
#      (dagu txe skill install), and every profile gets a link to it:
#        ~/.coding_skills/txe-dagu-jobs   -> $TXE_DAGU_HOME/skill/current, when ~/.coding_skills exists
#        <profile>/skills/txe-dagu-jobs   -> ~/.coding_skills/txe-dagu-jobs, or else skill/current
#      for every ~/.claude*, ~/.codex* and $CODEX_HOME (a home that is a link
#      is followed, and each real home is visited once), and ~/.agents/skills,
#      which Codex also reads. An entry already there that is not exactly such
#      a link (a real directory, or a link anywhere else, even to a matching
#      revision) is someone's: it is reported and kept.
#   5. It reads everything back: the wrapper is this script's and names the
#      installed binary and the developer's store; dagu on PATH is the link to
#      it; every location is exactly the managed link and resolves to this
#      binary's skill revision. Anything else fails the run.
#
# --check does step 5 only. It writes nothing and reads no context store: the
# skill status runs against an empty store in a temporary directory.
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
MARKER="# Written by txe/developer/install.sh"

die() { printf 'txe-dagu-cli: %s\n' "$*" >&2; exit 1; }
say() { printf '%-8s %s\n' "$1" "$2"; }
sum256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -c1-16; }

# realpath of a path whose last parts may not exist yet.
resolve() {
  python3 -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

# within says whether one resolved path is the other or below it.
within() {
  case "$1/" in "$2"/*) return 0 ;; esac
  return 1
}

# shell_quote prints a value as one single-quoted POSIX shell word.
shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

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

# swap_link points an existing link of ours at target: a link made under a
# fresh unique name in the same directory, then renamed over it.
swap_link() {
  python3 -I -c '
import os, sys
target, link = sys.argv[1], sys.argv[2]
d = os.path.dirname(link)
for _ in range(100):
    tmp = os.path.join(d, ".%s.%s" % (os.path.basename(link), os.urandom(6).hex()))
    try:
        os.symlink(target, tmp)
        break
    except FileExistsError:
        continue
os.replace(tmp, link)' "$1" "$2"
}

# stage copies or writes into a new file created only for this run, beside
# its destination, then renames it into place: nothing at a fixed temporary
# name is ever followed or reused.
stage_file() { # stage_file <dest> <mode>; content on stdin
  local tmp
  tmp="$(mktemp "$(dirname "$1")/.$(basename "$1").XXXXXX")"
  cat > "$tmp"
  chmod "$2" "$tmp"
  mv -f "$tmp" "$1"
}

# The profile homes on this machine, each real home once, with the skills
# directory to use in it; then the user-level directory Codex reads.
profiles() {
  local d real
  {
    for d in "$HOME"/.claude "$HOME"/.claude[0-9]* "$HOME"/.codex "$HOME"/.codex[0-9]* ${CODEX_HOME:+"$CODEX_HOME"}; do
      [ -d "$d" ] || continue
      real="$(resolve "$d")"
      printf '%s\n' "$real/skills"
    done
    if [ -d "$HOME/.agents" ] || [ -d "$HOME/.codex" ] || command -v codex >/dev/null 2>&1; then
      printf '%s\n' "$(resolve "$HOME/.agents")/skills"
    fi
  } | awk '!seen[$0]++'
}

# place_skill gives a skills directory its link to target, unless something
# that is not exactly that link is already there.
place_skill() {
  local dir="$1" target="$2" entry="$1/$SKILL" made
  if [ -L "$entry" ] && [ "$(readlink "$entry")" = "$target" ]; then
    say skill "$entry"
    return
  fi
  if [ -e "$entry" ] || [ -L "$entry" ]; then
    say kept "$entry is not a link to $target; left as it is"
    return
  fi
  mkdir -p "$dir"
  made="$(make_link "$target" "$entry")"
  case "$made" in
    made) say skill "$entry -> $target" ;;
    *) say kept "$entry: $made" ;;
  esac
}

wrapper="$TXE_DAGU_CLI_ROOT/bin/dagu"
link="$TXE_DAGU_LINK_DIR/dagu"
unpacked="$TXE_DAGU_HOME/skill/current"
store="$TXE_DAGU_CLI_ROOT/client/data"

# The developer's files and the worker's must not be the same place, or one
# install would write over the other. Compared as resolved paths, either way.
cli_real="$(resolve "$TXE_DAGU_CLI_ROOT")"
home_real="$(resolve "$TXE_DAGU_HOME")"
if within "$cli_real" "$home_real" || within "$home_real" "$cli_real"; then
  die "$TXE_DAGU_CLI_ROOT and the TXE home $TXE_DAGU_HOME are the same place or inside each other; give the developer CLI a root of its own"
fi
if within "$(resolve "$store")" "$home_real" || within "$(resolve "$TXE_DAGU_CLI_ROOT/bin")" "$home_real"; then
  die "$TXE_DAGU_CLI_ROOT/client or bin leads into the TXE home $TXE_DAGU_HOME, whose store and binary are the worker's"
fi

tag="" binary="" check=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --binary) binary="${2:-}"; shift 2 ;;
    --check) check=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ "$check" = 0 ]; then
  [[ "$tag" =~ ^txe-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]] || die "--tag must be txe-v<major>.<minor>.<patch>-<n>"
  version="${BASH_REMATCH[1]}-txe.${BASH_REMATCH[2]}"
  bin="$TXE_DAGU_CLI_ROOT/bin/dagu-$version"
  umask 022

  # 1. The binary: an accepted build given with --binary, or built from the tag.
  src="$(mktemp -d)"
  trap 'rm -rf "$src"' EXIT
  if [ -n "$binary" ]; then
    [ -f "$binary" ] && [ -x "$binary" ] || die "--binary $binary is not an executable file"
    built="$binary"
  else
    command -v go >/dev/null || die "go is not on PATH"
    git clone --quiet --depth 1 --branch "$tag" "$TXE_DAGU_REPO" "$src/dagu"
    (cd "$src/dagu" && GOTOOLCHAIN=auto go build -trimpath -ldflags "-X 'main.version=$version'" -o "$src/dagu.bin" ./cmd)
    built="$src/dagu.bin"
  fi
  got="$("$built" version 2>/dev/null | head -1)"
  [ "$got" = "$version" ] || die "the binary says it is version '$got', not $version ($tag)"
  mkdir -p "$TXE_DAGU_CLI_ROOT/bin"
  # The developer's context store: its key and sign-in context are this user's only.
  mkdir -p "$store" && chmod 0700 "$TXE_DAGU_CLI_ROOT/client" "$store"
  if [ -e "$bin" ] || [ -L "$bin" ]; then
    if [ ! -f "$bin" ] || [ -L "$bin" ] || ! cmp -s "$built" "$bin"; then
      die "$bin already exists and is not this build; move it away first"
    fi
  else
    stage_file "$bin" 0755 < "$built"
  fi
  say binary "$bin (sha256 $(sum256 "$bin"))"

  # 2. The wrapper, replaced as a whole. It finds the subcommand past the root
  # flag --context and its value, and puts the store flags right after txe.
  stage_file "$wrapper" 0755 <<EOF
#!/bin/sh
$MARKER ($tag). dagu txe commands use the
# developer's own context store; the machine's worker keeps its own.
binary=$(shell_quote "$bin")
store=$(shell_quote "$store")
n=0 at=0 skip=0
for arg do
    n=\$((n + 1))
    if [ "\$skip" = 1 ]; then skip=0; continue; fi
    case "\$arg" in
        --context) skip=1 ;;
        -*) ;;
        *) [ "\$arg" = txe ] && at=\$n; break ;;
    esac
done
if [ "\$at" -gt 0 ]; then
    i=0
    for arg do
        shift
        i=\$((i + 1))
        set -- "\$@" "\$arg"
        if [ "\$i" -eq "\$at" ]; then set -- "\$@" --contexts-dir "\$store/contexts" --data-dir "\$store"; fi
    done
fi
exec "\$binary" "\$@"
EOF
  say wrapper "$wrapper"

  # 3. dagu on PATH.
  worker_link="$TXE_DAGU_HOME/bin/dagu"
  if [ -L "$link" ] && { [ "$(readlink "$link")" = "$wrapper" ] || [ "$(readlink "$link")" = "$worker_link" ]; }; then
    swap_link "$wrapper" "$link"
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

  # 4. The skill, then a link in every profile. The skill command needs no
  # context store, so it is given an empty one of its own.
  "$bin" txe skill install --contexts-dir "$src/store/contexts" --data-dir "$src/store" >/dev/null
  if [ -d "$CODING_SKILLS" ]; then
    place_skill "$CODING_SKILLS" "$unpacked"
  fi
  if [ -d "$CODING_SKILLS" ]; then profile_target="$CODING_SKILLS/$SKILL"; else profile_target="$unpacked"; fi
  while IFS= read -r dir; do
    place_skill "$dir" "$profile_target"
  done < <(profiles)
fi

# 5. Read back.
failed=0
installed=""
if [ -f "$wrapper" ] && [ "$(sed -n 2p "$wrapper" | cut -c1-${#MARKER})" = "$MARKER" ]; then
  installed="$(python3 -I -c '
import shlex, sys
for line in open(sys.argv[1]):
    if line.startswith("binary="):
        print(shlex.split(line[len("binary="):])[0])
        break' "$wrapper")"
  if ! grep -qxF "store=$(shell_quote "$store")" "$wrapper" || [ ! -x "$installed" ]; then
    say wrapper "$wrapper does not name an installed binary and the developer's store $store"
    failed=1
  else
    say wrapper "$wrapper -> $installed, store $store"
  fi
else
  say wrapper "missing or not this script's: $wrapper"
  failed=1
fi
on_path="$(command -v dagu || true)"
if [ -n "$on_path" ] && [ "$on_path" = "$link" ] && [ -L "$link" ] && [ "$(readlink "$link")" = "$wrapper" ]; then
  say path "dagu -> $wrapper, version $(dagu version 2>/dev/null | head -1)"
else
  say path "dagu on PATH is ${on_path:-missing}, not $link -> $wrapper"
  failed=1
fi
locations=()
expect=()
if [ -d "$CODING_SKILLS" ]; then
  locations+=("$CODING_SKILLS"); expect+=("$unpacked")
  profile_target="$CODING_SKILLS/$SKILL"
else
  profile_target="$unpacked"
fi
while IFS= read -r dir; do locations+=("$dir"); expect+=("$profile_target"); done < <(profiles)
links=()
for i in "${!locations[@]}"; do
  entry="${locations[$i]}/$SKILL"
  if [ ! -L "$entry" ] || [ "$(readlink "$entry")" != "${expect[$i]}" ]; then
    say skill "$entry is not the link to ${expect[$i]}"
    failed=1
  fi
  links+=(--link "${locations[$i]}")
done
if [ -n "$installed" ] && [ -x "$installed" ]; then
  scratch="$(mktemp -d)"
  if ! "$installed" txe skill status --contexts-dir "$scratch/contexts" --data-dir "$scratch" "${links[@]}"; then
    failed=1
  fi
  rm -rf "$scratch"
else
  failed=1
fi
[ "$failed" = 0 ] || die "not every part is in place; see above"
echo "ok. Sign in with: dagu txe login --hub https://<the hub's address>"
