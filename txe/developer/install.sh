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
# --check does step 5 only. It changes nothing outside a temporary directory it
# removes, and reads no context store: the skill status runs with a Dagu home
# and store of its own there.
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

# swap_link points a link of ours at target: a link made under a fresh unique
# name in the same directory, then renamed over it, only if the pathname is
# still a link to one of the targets named. The check and the rename are two
# steps: another program replacing that link in between would lose its file.
# The lock serialises this script, not other programs.
swap_link() { # swap_link <target> <link> <allowed-target>...
  python3 -I -c '
import os, sys
target, link, allowed = sys.argv[1], sys.argv[2], sys.argv[3:]
d = os.path.dirname(link)
for _ in range(100):
    tmp = os.path.join(d, ".%s.%s" % (os.path.basename(link), os.urandom(6).hex()))
    try:
        os.symlink(target, tmp)
        break
    except FileExistsError:
        continue
if not os.path.islink(link) or os.readlink(link) not in allowed:
    os.unlink(tmp)
    sys.exit("%s changed while installing; it is left as it is" % link)
os.replace(tmp, link)' "$@"
}

# stage_file writes stdin into a new file created only for this run, beside
# its destination, then renames it onto exactly that pathname: a link there is
# replaced, never followed, and a directory there is refused.
stage_file() { # stage_file <dest> <mode>; content on stdin
  local tmp
  tmp="$(mktemp "$(dirname "$1")/.$(basename "$1").XXXXXX")"
  cat > "$tmp"
  chmod "$2" "$tmp"
  python3 -I -c '
import os, stat, sys
tmp, dest = sys.argv[1], sys.argv[2]
try:
    if stat.S_ISDIR(os.lstat(dest).st_mode):
        os.unlink(tmp)
        sys.exit("%s is a directory" % dest)
except FileNotFoundError:
    pass
os.replace(tmp, dest)' "$tmp" "$1" || die "could not write $1"
}

# publish_new puts a staged copy of a file at a pathname that must not exist
# yet. The hard link fails if anything appeared there, so two installs never
# overwrite each other's binary.
publish_new() { # publish_new <src> <dest>
  local tmp
  tmp="$(mktemp "$(dirname "$2")/.$(basename "$2").XXXXXX")"
  cat "$1" > "$tmp"
  chmod 0755 "$tmp"
  python3 -I -c '
import os, sys
tmp, dest = sys.argv[1], sys.argv[2]
try:
    os.link(tmp, dest)
finally:
    os.unlink(tmp)' "$tmp" "$2" || die "$2 appeared while installing; run the install again"
}

# wrapper_text is the wrapper for a tag and binary, exactly. The readback
# compares the installed wrapper with it byte for byte.
#
# It finds the subcommand the way dagu's command parser does: a long flag
# without "=" takes the next argument as its value (but --help), and so does a
# two-letter short flag (but -h). When that subcommand is txe, the developer's
# store flags go right after it.
wrapper_text() { # wrapper_text <tag> <binary>
  cat <<EOF
#!/bin/sh
$MARKER ($1). dagu txe commands use the
# developer's own context store; the machine's worker keeps its own.
binary=$(shell_quote "$2")
store=$(shell_quote "$store")
n=0 at=0 skip=0
for arg do
    n=\$((n + 1))
    if [ "\$skip" = 1 ]; then skip=0; continue; fi
    case "\$arg" in
        --help|-h|--*=*) ;;
        --*) skip=1 ;;
        -?) skip=1 ;;
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
for mine in "$TXE_DAGU_CLI_ROOT/bin" "$TXE_DAGU_CLI_ROOT/client" "$store"; do
  for theirs in "$TXE_DAGU_HOME" "$TXE_DAGU_HOME/bin" "$TXE_DAGU_HOME/client" "$TXE_DAGU_HOME/client/data" "$TXE_DAGU_HOME/client/data/contexts"; do
    a="$(resolve "$mine")" b="$(resolve "$theirs")"
    if within "$a" "$b" || within "$b" "$a"; then
      die "$mine and $theirs are the same place or inside each other; the worker's binary and store must stay apart from the developer's"
    fi
  done
done

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
  # One install at a time on this machine.
  mkdir -p "$TXE_DAGU_CLI_ROOT"
  lock="$TXE_DAGU_CLI_ROOT/.install.lock"
  mkdir "$lock" 2>/dev/null || die "another install is running (or one was stopped: remove $lock)"
  src=""
  trap 'rm -rf "${src:-}"; rmdir "$lock"' EXIT

  # 1. The binary: an accepted build given with --binary, or built from the tag.
  src="$(mktemp -d)"
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
    publish_new "$built" "$bin"
  fi
  say binary "$bin (sha256 $(sum256 "$bin"))"

  # 2. The wrapper, replaced as a whole.
  wrapper_text "$tag" "$bin" | stage_file "$wrapper" 0755
  say wrapper "$wrapper"

  # 3. dagu on PATH.
  worker_link="$TXE_DAGU_HOME/bin/dagu"
  if [ -L "$link" ] && { [ "$(readlink "$link")" = "$wrapper" ] || [ "$(readlink "$link")" = "$worker_link" ]; }; then
    if swap_link "$wrapper" "$link" "$wrapper" "$worker_link"; then
      say path "$link -> $wrapper"
    fi
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
  "$bin" txe skill install --dagu-home "$src/home" --contexts-dir "$src/home/contexts" --data-dir "$src/home/data" >/dev/null
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
installed="" wtag=""
if [ -f "$wrapper" ] && [ ! -L "$wrapper" ]; then
  installed="$(python3 -I -c '
import shlex, sys
for line in open(sys.argv[1]):
    if line.startswith("binary="):
        print(shlex.split(line[len("binary="):])[0])
        break' "$wrapper" 2>/dev/null || true)"
  line2="$(sed -n 2p "$wrapper")"
  rest="${line2#"$MARKER ("}"
  wtag="${rest%%)*}"
  [[ "$wtag" =~ ^txe-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]] || wtag=""
fi
# The binary must be the one this script installs for the wrapper's tag, and
# say it is that version.
want_bin="" want_version=""
if [[ "$wtag" =~ ^txe-v([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)$ ]]; then
  want_version="${BASH_REMATCH[1]}-txe.${BASH_REMATCH[2]}"
  want_bin="$TXE_DAGU_CLI_ROOT/bin/dagu-$want_version"
fi
if [ -n "$installed" ] && [ "$installed" = "$want_bin" ] && [ -f "$installed" ] && [ ! -L "$installed" ] && [ -x "$installed" ] &&
  [ "$("$installed" version 2>/dev/null | head -1)" = "$want_version" ] &&
  [ "$(wrapper_text "$wtag" "$installed")" = "$(cat "$wrapper")" ]; then
  say wrapper "$wrapper -> $installed ($want_version), store $store"
else
  say wrapper "missing or not this script's: $wrapper"
  installed=""
  failed=1
fi
on_path="$(command -v dagu || true)"
if [ -n "$on_path" ] && [ "$(resolve "$(dirname "$on_path")")" = "$(resolve "$TXE_DAGU_LINK_DIR")" ] && [ -L "$link" ] && [ "$(readlink "$link")" = "$wrapper" ]; then
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
  if ! "$installed" txe skill status --dagu-home "$scratch" --contexts-dir "$scratch/contexts" --data-dir "$scratch/data" "${links[@]}"; then
    failed=1
  fi
  rm -rf "$scratch"
else
  failed=1
fi
[ "$failed" = 0 ] || die "not every part is in place; see above"
echo "ok. Sign in with: dagu txe login --hub https://<the hub's address>"
