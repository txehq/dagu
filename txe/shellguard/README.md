# shellguard: refuse shell-evaluated text before a shell parses it (TXE-8055)

Agents put prose (message bodies, comments, PR bodies) into shell commands. Two quoting forms turn
that prose into commands:
- a double-quoted string;
- an unquoted here-document.

In either, a backtick or `$( )` is a command substitution. The shell runs it before the target
program starts.

On 2026-11-22 this ran a merge script and `flux suspend` against the production context. The
postmortem is txehq/txe `docs/postmortems/2026-11-22-coordination-text-executed-commands.md`.

A wrapper around the target program is too late, because the substitution has already run. So
`guard-hook.py` is a PreToolUse hook that reads the command **text** first.

**Status:** source only. Nothing installs or registers this hook. Installation is TXE-8120, and it
waits on three things:
- this code, merged;
- the payload routes, validated against captured real-runtime input;
- Connor's approval.

## Rules

An **active** command substitution is a `$(` that is not `$((`, or an unescaped backtick, where the
shell would run it. Its nearest quoting context decides:

| Rule | Where | Decision |
|---|---|---|
| D1 | backtick inside double quotes | refuse |
| T2 | `$( )` inside double quotes, whatever the CLI, flag or length | refuse |
| H1 | either one in the body of an unquoted heredoc (`<<EOF`, `<<-EOF`) | refuse |
| U1 | backtick in unquoted code | refuse (write `$( )`) |
| none | `$( )` in unquoted code (`V=$(cmd)`, `cmd $(other)`) | allowed: code, not prose |

The rules key on the shell construct, never on a CLI name. The tests check the same constructs
under invented CLIs.

**Rewrites:**
- **Prose:** write it to a file with the Write tool, then pass the file with `--body-file`, `-F`
  or `git commit -F`.
- **A computed value:** `V=$(cmd)` first, then pass `"$V"`. A plain `"$V"` is expanded once and
  is not parsed again.

**Allowed:** `'…'`, `$'…'`, `"\$(x)"`, a quoted heredoc delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`,
`<<E'O'F`), and comments.

**Refused visibly, because the scanner cannot follow the input:**
- X1: a construct left open at the end of the input.
- B1: input over 256 KiB.
- B2: nesting deeper than 64.

The bounds count **UTF-8 bytes**. The scan is a single forward pass, and findings are capped at 20.

## Payload routes

`tool_input` is read as data. Argv is never joined into a synthetic shell string.

| `tool_input` | Treatment |
|---|---|
| no `command`/`cmd` key | allowed: not command-bearing, so non-shell tools pass |
| `command`/`cmd` is a string | scanned as a shell command string |
| a list whose `argv[0]` is `sh`, `bash`, `zsh`, `dash` or `ksh`, and whose options include `-c` | only the script operand is scanned. Options are parsed by that shell's own grammar: `-o NAME`, bash's `-O SHOPT`, bash's long options, zsh's `--emulate`. |
| any other list of strings | a direct exec: every element is an inert argument. `echo bash -c TEXT` is inert. |
| P0 | refused visibly: hook input that is not UTF-8 JSON, or over the byte bound (one bounded read, before any decode) |
| P1 | refused visibly: an unsupported command shape |
| P2 | refused visibly: an option outside the shell's modelled grammar, or `-c` with no script |
| P3 | refused visibly: a non-POSIX shell (fish, csh, …) |
| P4 | refused visibly: a shell run through a wrapper (`env`, `timeout`, `sudo`, `xargs`, …) |

The Claude Code payload shape is documented. **The Codex payload shape is not verified here.** One
sanitized real payload per runtime has to be captured, as data, before any installation is
accepted.

**Protocol:**
- A refusal exits 2 with the reason on stderr.
- Anything else prints nothing and exits 0.
- An internal error refuses, naming its type.

## Known limits (pinned by tests as allowed)

- **Text a second parser runs:** `sh -c '…'`, `eval "$x"`, `bash <<'EOF'`, `ssh host '…'`,
  `python3 -c '…'`.
- **A script file run later:** `bash ./script.sh`, `bash -s`.
- **Command text built at run time.**
- **`case … in a)` inside `$( )`:** an early `)` fails toward refusing.

This guard removes one class of accident. It does not make a shell command safe.

## Reviewed call graph: what fixture text can reach

The entry points are `check(text)` and `main(stdin, stderr)`.

`main` makes these calls, and no others:
- `stdin.read(MAX_BYTES + 1)`: one bounded read;
- `bytes.decode("utf-8")`;
- `json.loads`;
- `command_texts(payload)`, which calls `classify_argv(argv)` for lists. It returns strings only.
- `check(text)` for each string. That is `Scanner(text).scan()`: a state machine over the string,
  using `str` methods (`startswith`, `find`, `lstrip`, `join`), with a nested `Scanner` for heredoc
  bodies;
- `print(reason, file=stderr)`;
- a return of the exit status. `sys.exit` is called only under `__main__`.

The module imports only `json` and `sys`. Fixture text is only ever an argument to `check()`, or
bytes on `main()`'s stream. It is never passed to a parser that executes anything.

`test_guard_hook.py`'s `Structure` class pins:
- the import list;
- every called name;
- every called attribute;
- the absence of computed callees and dynamic attribute access.

This is **regression detection**: a new call fails the test and gets reviewed. It is not a proof of
zero execution on its own.

## Tests

`shellguard_test.go` runs `python3 -I -B test_guard_hook.py -v` in dagu CI, through `ci.yaml`
paths `txe/**`. The suite is text-only:
- the fixtures are strings;
- the incident fixtures are sanitized shapes with placeholder command words;
- no process, file or network is used beyond reading the guard's own source.

The real-shell positive controls are a separate, isolated container plan (TXE-8055 run C), under
its own grant.
