#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""PreToolUse hook (TXE-8039): an agent's cluster API call goes through kube-run, or it is refused. This is
source only: nothing installs or wires it. Once wired, it BLOCKS calls: with no cluster registered, every
cluster API call an agent makes is refused.

Why: on 2026-11-21 at 07:14:57Z an agent ran `timeout 30 kubectl get gitrepositories... -A` with no
--context and no --kubeconfig. That workstation's default context is the production cluster, so the read went
to production. Naming a context or a kubeconfig is self-asserted metadata, not cluster identity, so the job of
identity belongs to kube-run (kube_run.py beside this file). kube-run pins the server and CA before contact
and checks the kube-system UID at contact. This hook only makes sure that kube-run is the path:

  - A direct kubectl/oc/kubecolor API call is refused (H01), however fully it names its target.
  - A helm, flux, k9s or stern API call is refused (H07). That is a COMPATIBILITY DECISION, not an approved
    deployment policy. These clients have no identity-bound path yet, and whether to give them one, or
    another rule, is a decision for any install plan.
  - `<installed kube-run> [--authorization F] [--timeout N] <cluster-id> -- <kubectl args>` is let through
    when kube-run is the installed path (H09), its own arguments are well formed (H10), and the kubectl
    arguments carry no target, identity or TLS override (H11). It must be the BARE command word, in a line that
    changes no environment at any depth (H16): an assignment, `export`/`declare`/`unset`/`source`/`hash`/..., or a
    wrapper (`env`, `sudo`, `timeout`, `time`, ...) could choose the interpreter of its `env python3` shebang.
    An install starts kube-run through an absolute pinned interpreter in isolated mode; the shebang is for running
    it from source (see the README's installation contract). kube-run repeats every check at run time,
    on the arguments it actually receives. kube-run is read-only, and refuses every mutating, interactive or
    tunnelling verb itself.
  - Local commands need nothing: kubectl version --client, help/--help/-h, completion, options, plugin list,
    kustomize, config current-context|get-contexts|get-clusters|get-users|view (not --raw/--flatten, H08);
    helm version|template (not --validate)|lint|package|repo|show|pull|dependency|...; flux version --client,
    --export, OCI artifact commands; and the kustomize binary (no cluster client; --enable-helm runs
    helm template locally). kubectx, kubens, gcloud get-credentials and config writes to the default
    kubeconfig are refused (H06).

It fails closed. A client reached through something the hook cannot see into is refused: a command word built
at run time (H02); a client inside python -c, ssh, find -exec, docker and the like (H03); an assignment or
alias whose value is a client (H04); a command or nested shell text it cannot parse, whatever it names (H05);
nesting too deep (H12).
sh/bash/zsh -c, eval, here-documents and here-strings fed to a shell, $(...), backticks and <(...) are parsed
recursively, and wrappers (timeout, env, xargs, watch, sudo, nice, nohup, ...) are unwrapped. A wrapper option
the hook does not know may take a value, so it cannot tell which word is the command: when a cluster client
follows it, the command is refused (H03).

POSITIVE CLASSIFICATION (H15): a client's name is accepted only in a context the hook understands. Those are a
client's own classified argv, the installed kube-run's argv, a command of the SMALL closed data set (DATA_OPTIONS:
echo, printf, cat, grep, which, test) with only its listed options and whose output does not reach a shell or
interpreter, `command -v`, and substitutions classified recursively. man and git are not accepted. Anywhere else it is refused. This is not containment of arbitrary scripts or interpreters: commands
absent from the text (script files, run-time names, earlier aliases) cannot be seen.

Diagnostics are value-free. They give the client and the subcommand only when each is in the hook's fixed
lists, a stable rule id, and the location as a simple-command index with a character span. The span is
counted in the command after line continuations are removed. No argument, flag value, path, context name
or command text is printed.

Event shapes. Only ONE shape is positively guarded: a Claude Code PreToolUse event whose tool_name is "Bash"
and whose tool_input.command is a string. Everything above applies to that shape only. Any other event is
NOT guarded, and the hook does not count it as protected:
  - an event of another tool or harness that carries a command-like field (tool_input.command or
    tool_input.cmd, a string or an argv list), for example a Codex shell call, is refused (H14) when the
    field's text names a cluster client, and allowed otherwise. That is a fail-closed stop on an unsupported
    shape, not a guard: nothing in it is parsed, and no Codex payload has been captured or tested;
  - an event with no command-like field (Read, Edit, MCP tools, ...) is allowed. MCP cluster tools are out of
    scope (TXE-7874).
Input that is not a JSON object is refused (H13) when it names a cluster client.

What it cannot see: script files (`bash ops/x.sh` that runs kubectl inside), client-go programs, and the tools
of the shapes above that it does not guard. It never contacts a cluster, never runs a client and never opens a
kubeconfig.

Usage (hook command): kubectl-context-guard.py [--kube-run PATH]   (default ~/.coding_global/bin/kube-run)
"""
import json
import os
import re
import shlex
import sys

DEFAULT_KUBE_RUN = "~/.coding_global/bin/kube-run"
MAX_DEPTH = 6

FAMILY = {"kubectl": "kubectl", "oc": "kubectl", "kubecolor": "kubectl", "microk8s.kubectl": "kubectl",
          "helm": "helm", "flux": "flux", "k9s": "k9s", "stern": "stern"}
GLOBAL_MUTATORS = {"kubectx", "kubens"}
LOCAL_ONLY = {"kustomize"}
VENDOR_WRAPPERS = {"k3s", "microk8s", "minikube"}
KUBE_RUN_NAMES = {"kube-run", "kube_run.py", "kube-run.py"}
CLIENT_NAMES = sorted(set(FAMILY) | GLOBAL_MUTATORS, key=len, reverse=True)
# "!" is in the left context too: git and shell aliases run `!kubectl ...`.
MENTION = re.compile(r"(?:^|(?<=[\s'\"`(;|&=\[,{!]))(?:[\w.~-]*/)*(?:" + "|".join(map(re.escape, CLIENT_NAMES))
                     + r")(?=$|[\s'\"`);|&,\]}:@])")
CLUSTER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")

VALUE_FLAGS = {
    "kubectl": {"--context", "--kubeconfig", "-n", "--namespace", "-s", "--server", "--cluster", "--user",
                "--token", "--as", "--as-group", "--as-uid", "--request-timeout", "--cache-dir",
                "--certificate-authority", "--client-certificate", "--client-key", "--tls-server-name",
                "--username", "--password", "-v", "--v", "--vmodule", "--log-file", "--log-dir", "--profile",
                "--profile-output", "-o", "--output", "-l", "--selector", "-f", "--filename", "-c",
                "--container", "--field-selector", "--template"},
    "helm": {"--kube-context", "--kubeconfig", "-n", "--namespace", "--kube-apiserver", "--kube-token",
             "--kube-as-user", "--kube-as-group", "--kube-ca-file", "--kube-tls-server-name", "--registry-config",
             "--repository-cache", "--repository-config", "--burst-limit", "--qps", "-o", "--output", "-f",
             "--values", "--set", "--version"},
    "flux": {"--context", "--kubeconfig", "-n", "--namespace", "--timeout", "--server", "--cluster", "--user",
             "--token", "--as", "--as-group", "--as-uid", "--cache-dir", "--certificate-authority",
             "--client-certificate", "--client-key", "--tls-server-name", "--request-timeout", "--path",
             "--url", "--source", "-o", "--output"},
    "k9s": {"--context", "--kubeconfig", "-n", "--namespace", "--cluster", "--user", "--token", "--as",
            "--as-group", "-c", "--command", "-l", "--logLevel"},
    "stern": {"--context", "--kubeconfig", "-n", "--namespace", "-s", "--since", "-c", "--container", "-l",
              "--selector", "-o", "--output", "--template"},
}
# kube-run refuses these in its kubectl arguments too (kube_run.OVERRIDE_FLAGS); the hook refuses them early.
KUBE_RUN_OVERRIDES = ("--kubeconfig", "--context", "--server", "-s", "--cluster", "--user", "--token",
                      "--username", "--password", "--as", "--as-group", "--as-uid", "--certificate-authority",
                      "--client-certificate", "--client-key", "--tls-server-name", "--insecure-skip-tls-verify",
                      "--kuberc")
KUBECTL_LOCAL_1 = {"help", "completion", "options", "kustomize"}
KUBECTL_CONFIG_READ = {"current-context", "get-contexts", "get-clusters", "get-users", "view"}
HELM_LOCAL = {"version", "help", "completion", "env", "template", "lint", "package", "create", "show",
              "inspect", "pull", "fetch", "push", "repo", "search", "dependency", "dep", "plugin", "registry",
              "verify"}
FLUX_OCI = {"push", "pull", "tag", "list", "diff"}
CLUSTER_VERBS = {"get", "describe", "apply", "delete", "create", "edit", "patch", "replace", "logs", "exec",
                 "port-forward", "proxy", "rollout", "scale", "top", "auth", "cp", "attach", "run", "expose",
                 "label", "annotate", "drain", "cordon", "uncordon", "taint", "wait", "events", "api-resources",
                 "api-versions", "cluster-info", "explain", "diff", "debug", "autoscale", "certificate",
                 "install", "upgrade", "uninstall", "rollback", "reconcile", "suspend", "resume", "bootstrap",
                 "history", "status", "list"}
# Subcommands the diagnostics may name. Anything else is reported as <other>.
SAFE_SUBCOMMANDS = CLUSTER_VERBS | KUBECTL_LOCAL_1 | HELM_LOCAL | {"version", "config", "plugin", "build",
                                                                   "export", "envsubst", "info"}

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "time", "coproc"}
OPAQUE = {"ssh", "find", "parallel", "su", "script", "expect", "tmux", "screen", "docker", "podman", "nsenter",
          "chroot", "flock", "rsudo", "osascript", "alias", "trap", "nix-shell", "devbox", "make", "just",
          "launchctl", "at", "crontab", "open"}
INTERPRETERS = re.compile(r"^(python[\d.]*|node|nodejs|deno|bun|perl|ruby|php|lua|tclsh|Rscript|osascript)$")
# wrapper -> its options that take a separate value.
WRAPPERS = {
    "env": {"-u", "--unset", "-C", "--chdir", "-P", "-S", "--split-string"},
    "command": set(), "exec": {"-a"}, "builtin": set(), "nohup": set(), "time": set(),
    "nice": {"-n", "--adjustment"}, "caffeinate": {"-t", "-w"}, "stdbuf": {"-i", "-o", "-e"},
    "unbuffer": set(),
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-U", "-r", "-t", "-T", "--user", "--group", "--prompt",
             "--close-from", "--chdir", "--role", "--type", "--other-user", "--host", "--command-timeout"},
    "doas": {"-u", "-C"}, "watch": {"-n", "--interval"},
    "xargs": {"-I", "-n", "-L", "-P", "-s", "-d", "-E", "-a", "--max-procs", "--max-args",
              "--delimiter", "--arg-file", "--max-chars"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"}, "gtimeout": {"-s", "--signal", "-k", "--kill-after"},
}
# wrapper -> its options known to take NO value. Any option in neither set may take one, so the word after it
# cannot be placed: if what follows names a cluster client, the command is refused (H03), never guessed.
WRAPPER_FLAGS = {
    "env": {"-i", "--ignore-environment", "-0", "--null", "-v", "--debug"},
    "command": {"-p"}, "exec": {"-c", "-l"},
    "sudo": {"-A", "-B", "-b", "-E", "-e", "-H", "-i", "-K", "-k", "-l", "-n", "-P", "-S", "-s", "-V", "-v",
             "--askpass", "--background", "--preserve-env", "--set-home", "--login", "--remove-timestamp",
             "--reset-timestamp", "--non-interactive", "--preserve-groups", "--stdin", "--shell"},
    "doas": {"-n", "-s"}, "caffeinate": {"-d", "-i", "-m", "-s", "-u"}, "unbuffer": {"-p"},
    "watch": {"-t", "--no-title", "-e", "--errexit", "-g", "--chgexit", "-b", "--beep", "-c", "--color", "-x",
              "--exec", "-p", "--precise"},
    "xargs": {"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "--interactive", "-x", "--exit"},
    "timeout": {"--preserve-status", "--foreground", "-v", "--verbose"},
    "gtimeout": {"--preserve-status", "--foreground", "-v", "--verbose"},
}
# wrapper -> its options whose value is OPTIONAL and can only be attached (GNU getopt `x::`): the bare form takes
# NO value, so the next word is never consumed (`watch -d 'kubectl get secrets'` runs the quoted command). An
# attached short form (`-d1`, `-ifoo`) is not modelled and is treated as unknown (fail closed); `--long=value`
# takes nothing from the next word.
OPTIONAL_VALUE = {
    "watch": {"-d", "--differences"},
    "xargs": {"-i", "--replace", "-e", "--eof", "-l", "--max-lines"},
}
DURATION_WRAPPERS = {"timeout", "gtimeout"}
# Shell builtins that change the environment or the command lookup of the rest of the line. kube-run's
# `#!/usr/bin/env python3` lets the environment choose its interpreter, so with one of these (or any assignment)
# anywhere in the line, an installed kube-run invocation is refused (H16).
# `set` is not listed: `set -a` only exports later assignments, and every assignment is already counted.
ENV_BUILTINS = {"export", "declare", "typeset", "local", "readonly", "unset", "alias", "unalias", "hash",
                "enable", "shopt", "source", "."}
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
DYNAMIC = re.compile(r"[$`*?\[]")

RULES = {
    "H01": "a direct kubectl API call; agents reach a cluster only through kube-run",
    "H02": "the command word is built at run time, so the hook cannot tell which client it runs",
    "H03": "a cluster client is run through an interpreter or executor whose payload the hook cannot parse",
    "H04": "an assignment or alias hides a cluster client",
    "H05": "the command could not be read, so it is refused whatever it names",
    "H06": "the command changes the default kubeconfig or its current context",
    "H07": "a helm, flux, k9s or stern API call; these have no identity-bound path (compatibility decision, open)",
    "H08": "the command prints kubeconfig credentials",
    "H09": "kube-run is not the installed kube-run",
    "H10": "kube-run's own arguments are malformed (options, a literal registered-style cluster id, then --)",
    "H11": "kube-run's kubectl arguments override the target, identity or TLS",
    "H12": "the command nests shells or substitutions too deeply to read",
    "H13": "the hook input could not be read, or the hook failed, and the input names a cluster client",
    "H14": "this tool or event shape is not one the hook guards, and its command names a cluster client",
    "H15": "a cluster client is named in a position the hook does not understand (only data-only commands may "
           "carry its name as text)",
    "H16": "kube-run is started through a wrapper, or the line changes the environment (an assignment, export, "
           "source, ...), which could choose its interpreter; run the installed kube-run as a bare command",
}
# ACCEPTED DATA CONTEXTS: a SMALL CLOSED SET of inert forms. A client's name may appear as data only in these
# commands, only with the options listed (no-value short letters, value-taking short letters, long options), and
# only while the output does not reach code. A shell, eval, source or interpreter reading the pipe, or an output
# process substitution >(...) (checked as a pipe receiver), is refused when the command names a client.
# None of these runs a program named by an operand or an option: they print, read files or match text. Any other
# command (man, git, less, sort, rg, gh, orca, ...), any option not listed, and any attached or clustered form
# outside the table make the command unclassified, which is H15 when it names a client. man (its pager) and git
# (configured hooks, pagers, diff drivers and textconv helpers that no flag reveals) are deliberately NOT
# accepted: their full semantics are not modelled here. In a short cluster, a value letter ends it (the rest, or
# the next word, is its value). "any" takes any token (test, [: they evaluate an expression and run nothing).
DATA_OPTIONS = {
    "echo": ("neE", "", set()),
    "printf": ("", "", set()),
    "cat": ("", "", set()),
    "grep": ("rRnilcvwxEFo", "e", set()), "egrep": ("rRnilcvwxo", "e", set()), "fgrep": ("rRnilcvwxo", "e", set()),
    "which": ("a", "", set()),
    # `[` (the test command with its closing `]`) is classified before the DYNAMIC check in _command, with test's
    # rules; it is listed here only to document that.
    "test": "any", "[": "any", "true": "any", "false": "any", ":": "any",
}
DATA_ONLY = set(DATA_OPTIONS)


def options_in_table(args, spec):
    """True when every option in args is in `spec` (see DATA_OPTIONS); operands are free text."""
    if spec == "any":
        return True
    bools, values, longs = spec
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return True
        if a.startswith("--"):
            if a.partition("=")[0] not in longs:
                return False
        elif a.startswith("-") and len(a) > 1:
            for k, ch in enumerate(a[1:], 1):
                if ch in values:
                    if k == len(a) - 1:
                        i += 1          # the value is the next word
                    break
                if ch not in bools:
                    return False
        i += 1
    return True

class ParseError(Exception):
    pass


# ---- a small shell lexer -------------------------------------------------------------------
OPERATORS = ["<<<", "<<-", "&&", "||", ";;", "|&", ">>", "<<", ">&", "<&", "&>", ">|", "<>", "|", "&", ";",
             "<", ">", "(", ")", "\n"]
SEPARATORS = {";", "&&", "||", ";;", "|", "|&", "&", "(", ")", "\n"}
REDIRECTS = {">>", ">&", "<&", "&>", ">|", "<>", "<", ">"}


def _balanced(s, i, open_ch, close_ch):
    """Index just past the close that matches s[i-1] == open_ch, honouring quotes. Raises on no match."""
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("unterminated quote")
            i = j + 1
            continue
        if c == '"':
            i = _dquote_end(s, i + 1)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ParseError("unbalanced " + open_ch)


def _dquote_end(s, i):
    """Index just past the closing double quote, for a string whose opening quote is at i-1."""
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if s.startswith("$(", i):
            i = _balanced(s, i + 2, "(", ")")
            continue
        if c == "`":
            j = _backtick_end(s, i + 1)
            i = j
            continue
        i += 1
    raise ParseError("unterminated double quote")


def _backtick_end(s, i):
    n = len(s)
    while i < n:
        if s[i] == "\\":
            i += 2
            continue
        if s[i] == "`":
            return i + 1
        i += 1
    raise ParseError("unterminated backtick")


def lex(s):
    """Tokens: ("w", text, flags, start, end) for words and ("op", op) for operators; ("hd", index) marks a
    here-document whose body is bodies[index]. Word flags: {"ansi"} when $'...' quoting was used. start/end
    are offsets in the text after line continuations are removed (for value-free diagnostics)."""
    s = s.replace("\\\r\n", "").replace("\\\n", "")
    toks, bodies, pending = [], [], []
    i, n = 0, len(s)
    buf, started, flags, wstart = [], False, set(), 0

    def end_word():
        nonlocal buf, started, flags
        if started:
            toks.append(("w", "".join(buf), flags, wstart, i))
        buf, started, flags = [], False, set()

    while i < n:
        c = s[i]
        if not started:
            wstart = i
        if c in " \t\r":
            end_word()
            i += 1
        elif c == "#" and not started:
            j = s.find("\n", i)
            i = n if j < 0 else j
        elif c == "\\":
            if i + 1 < n:
                buf.append(s[i + 1])
            started = True
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("unterminated single quote")
            buf.append(s[i + 1:j])
            started = True
            i = j + 1
        elif c == "$" and s.startswith("$'", i):
            j, k = i + 2, None
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == "'":
                    k = j
                    break
                j += 1
            if k is None:
                raise ParseError("unterminated $' quote")
            buf.append(s[i:k + 1])
            flags = flags | {"ansi"}
            started = True
            i = k + 1
        elif c == '"':
            j = _dquote_end(s, i + 1)
            inner = s[i + 1:j - 1]
            buf.append(re.sub(r'\\([$`"\\])', r"\1", inner))
            started = True
            i = j
        elif c == "$" and s.startswith("$(", i):
            j = _balanced(s, i + 2, "(", ")")
            buf.append(s[i:j])
            started = True
            i = j
        elif c == "$" and s.startswith("${", i):
            j = _balanced(s, i + 2, "{", "}")
            buf.append(s[i:j])
            started = True
            i = j
        elif c == "`":
            j = _backtick_end(s, i + 1)
            buf.append(s[i:j])
            started = True
            i = j
        elif c in "<>" and s.startswith("(", i + 1):
            end_word()
            j = _balanced(s, i + 2, "(", ")")
            toks.append(("w", s[i:j], set(), i, j))
            i = j
        elif c in "|&;<>()\n":
            if c in "<>" and started and not flags and "".join(buf).isdigit():
                buf, started = [], False  # an fd number: 2>&1
            end_word()
            op = next(o for o in OPERATORS if s.startswith(o, i))
            i += len(op)
            if op in ("<<", "<<-"):
                m = re.match(r"[ \t]*(['\"]?)([^\s'\";|&<>()]+)\1", s[i:])
                if not m:
                    raise ParseError("here-document without a delimiter")
                # Bash removes quoting from the delimiter word (<<\EOF, <<'EOF', <<"EOF" all end at a line EOF).
                pending.append((re.sub(r"[\\'\"]", "", m.group(2)), op == "<<-", len(bodies)))
                toks.append(("hd", len(bodies)))
                bodies.append("")
                i += m.end()
                continue
            toks.append(("op", op))
            if op == "\n" and pending:
                for delim, strip, idx in pending:
                    lines = []
                    while True:
                        if i >= n:
                            raise ParseError("unterminated here-document")
                        j = s.find("\n", i)
                        line = s[i:] if j < 0 else s[i:j]
                        i = n if j < 0 else j + 1
                        if (line.lstrip("\t") if strip else line) == delim:
                            break
                        lines.append(line)
                    bodies[idx] = "\n".join(lines)
                pending = []
        else:
            buf.append(c)
            started = True
            i += 1
    end_word()
    if pending:
        raise ParseError("unterminated here-document")
    return toks, bodies


def simple_commands(s):
    """Split into simple commands: {"words": [(text, flags)], "stdin": [texts fed by << or <<<]}."""
    toks, bodies = lex(s)
    cmds, cur, skip_next, herestr = [], {"words": [], "stdin": []}, False, False
    for t in toks:
        if t[0] == "op":
            op = t[1]
            if op in SEPARATORS:
                cmds.append(cur)
                # A pipe edge is kept: the next command READS what the previous one writes.
                cur = {"words": [], "stdin": [], "piped": op in ("|", "|&")}
            elif op in REDIRECTS:
                skip_next = True
            elif op == "<<<":
                herestr = True
            continue
        if t[0] == "hd":
            cur["stdin"].append(bodies[t[1]])
            continue
        if skip_next:
            skip_next = False
            cur.setdefault("redirect_targets", []).append(t[1])
            continue
        if herestr:
            herestr = False
            cur["stdin"].append(t[1])
            continue
        cur["words"].append((t[1], t[2], t[3], t[4]))
    cmds.append(cur)
    for c in cmds:
        # The command's own source text, quotes included: a client named inside an attached option value
        # (`-O'kubectl get ns'`) has no word boundary in the unquoted word, but does in the source.
        ws = c["words"]
        c["raw"] = s[ws[0][2]:ws[-1][3]] if ws else ""
    return [c for c in cmds if c["words"] or c["stdin"]]


def substitutions(text):
    """The inner text of every $(...), `...` and <(...)/>(...) in a word."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("$(", i) or (text[i] in "<>" and text.startswith("(", i + 1)):
            j = _balanced(text, i + 2, "(", ")")
            out.append(text[i + 2:j - 1])
            i = j
        elif text[i] == "`":
            j = _backtick_end(text, i + 1)
            out.append(text[i + 1:j - 1])
            i = j
        else:
            i += 1
    return out


def output_substitutions(text):
    """The inner text of every OUTPUT process substitution >(...) in a word (a subset of substitutions())."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith(">(", i):
            j = _balanced(text, i + 2, "(", ")")
            out.append(text[i + 2:j - 1])
            i = j
        else:
            i += 1
    return out


# A client named as the attached value of a short option (`man -Pkubectl`, `git grep -Okubectl`): the option
# letters leave no word boundary before the name, so MENTION alone would miss it.
MENTION_ATTACHED = re.compile(r"(?:^|(?<=[\s'\"`(;|&=\[,{!]))-[A-Za-z]{1,4}(?:[\w.~-]*/)*(?:"
                              + "|".join(map(re.escape, CLIENT_NAMES)) + r")(?=$|[\s'\"`);|&,\]}:@])")


def mentions(text):
    # Also on a copy without backslashes: bash removes them (`kube\ctl` runs kubectl).
    texts = (text, text.replace("\\", "")) if "\\" in text else (text,)
    return any(MENTION.search(t) or MENTION_ATTACHED.search(t) for t in texts)


class Refusal(Exception):
    def __init__(self, rule, client=None, sub=None):
        super().__init__(rule)
        self.rule, self.client, self.sub = rule, client, sub
        self.where, self.nested = None, False


def safe_client(name):
    return name if name in FAMILY or name in GLOBAL_MUTATORS or name in ("gcloud", "kube-run") else None


def safe_sub(name):
    return name if name in SAFE_SUBCOMMANDS else "<other>"


class Guard:
    def __init__(self, kube_run, cwd, whole):
        self.kube_run = kube_run
        self.cwd = cwd
        self.whole_mentions = mentions(whole)
        # H16: whether any command of the line (at any depth) changes the environment, and the top-level command
        # index of the first installed kube-run invocation the hook accepted.
        self.env_changed = False
        self.kube_run_at = None
        self._top_k = 0

    # Top level: locate a refusal by simple-command index and character span.
    def check_top(self, text):
        try:
            cmds = simple_commands(text)
        except ParseError:
            # A command the hook cannot parse is ambiguous: refused whether or not its raw text names a client,
            # because bash may unquote what the text hides (`kube\ctl ... <<\EOF`).
            raise Refusal("H05")
        for k, cmd in enumerate(cmds, 1):
            self._top_k = k
            try:
                self.check_cmd(cmd, 0)
            except Refusal as r:
                ws = cmd["words"]
                span = (ws[0][2], ws[-1][3]) if ws else (0, 0)
                r.where = (k, len(cmds), span)
                raise
        if self.kube_run_at is not None and self.env_changed:
            # One Bash event is one shell: an assignment or export anywhere in it (`PATH=/tmp/bin; kube-run ...`,
            # `export PATH=...`) reaches kube-run's `env python3` lookup, in whichever order the hook saw them.
            r = Refusal("H16", "kube-run")
            ws = cmds[self.kube_run_at - 1]["words"]
            r.where = (self.kube_run_at, len(cmds), (ws[0][2], ws[-1][3]) if ws else (0, 0))
            raise r

    def check_text(self, text, depth, piped=False):
        """A nested text: a -c string, eval's arguments, a here-document fed to a shell, a substitution.
        piped=True when the text's first command reads another command's output (an output process
        substitution)."""
        if depth > MAX_DEPTH:
            if mentions(text):
                raise Refusal("H12")
            return
        try:
            cmds = simple_commands(text)
        except ParseError:
            # Nested text is a shell program (-c, eval, a here-document fed to a shell): the same rule applies.
            r = Refusal("H05")
            r.nested = True
            raise r
        if piped and cmds:
            cmds[0]["piped"] = True
        for cmd in cmds:
            try:
                self.check_cmd(cmd, depth)
            except Refusal as r:
                r.nested = True
                raise

    def check_cmd(self, cmd, depth):
        texts = [w[0] for w in cmd["words"]] + cmd.get("redirect_targets", []) + cmd["stdin"]
        for t in texts:
            if "$(" not in t and "`" not in t and "(" not in t:
                continue
            try:
                inners = substitutions(t)
            except ParseError:
                if mentions(t):
                    raise Refusal("H05")
                continue
            out_inners = output_substitutions(t)
            for inner in inners:
                # An output process substitution >(...) READS what the command writes: its first command is
                # checked as a pipe receiver (`echo kubectl ... > >(bash)`, `... | tee >(sh)`).
                self.check_text(inner, depth + 1, piped=inner in out_inners)
        self._command(cmd, depth)

    def _command(self, cmd, depth):
        words = [(w[0], w[1]) for w in cmd["words"]]
        env = {}
        wrapped = False           # H16: kube-run must be the bare command word, not run through a wrapper
        while words and words[0][0] in KEYWORDS:
            wrapped = wrapped or words[0][0] in ("time", "coproc")
            words.pop(0)
        words = self._take_assignments(words, env)
        while words:
            w, fl = words[0]
            if w == "[" and "ansi" not in fl:
                # The exact command word `[` is the POSIX test command, not a glob: classified HERE, before the
                # generic DYNAMIC check. It needs its closing `]` as the last argument; malformed bracket syntax is
                # refused (H05). It then gets test's rules: its arguments are data (an expression; it runs
                # nothing), and any substitution in them was already classified recursively in check_cmd.
                # Only the exact word: `[a-z]`, `[k]ubectl` or `x[` stay run-time command words (H02).
                if len(words) < 2 or words[-1][0] != "]":
                    raise Refusal("H05")
                return
            if "ansi" in fl or DYNAMIC.search(w):
                args = [x[0] for x in words[1:]]
                operand = first_operand(args)
                if (self.whole_mentions or operand in CLUSTER_VERBS
                        or any(a in CLUSTER_FLAGS or a.split("=", 1)[0] in CLUSTER_FLAGS for a in args)):
                    raise Refusal("H02", None, safe_sub(operand))
                return
            base = os.path.basename(w)
            if base in WRAPPERS:
                wrapped = True
                words = self._unwrap(base, words[1:], env, depth)
                if words is None:
                    return
                continue
            if base in VENDOR_WRAPPERS and len(words) > 1 and os.path.basename(words[1][0]) == "kubectl":
                rest = words[2:]
                words = [("kubectl", set())] + (rest[1:] if rest and rest[0][0] == "--" else rest)
                continue
            break
        if not words:
            for stdin in cmd["stdin"]:
                if mentions(stdin):
                    raise Refusal("H03")
            return
        w = words[0][0]
        base = os.path.basename(w)
        args = [x[0] for x in words[1:]]
        if base in ENV_BUILTINS:
            self.env_changed = True
        runs_text = base in SHELLS or base in ("eval", "source", ".") or bool(INTERPRETERS.match(base))
        if runs_text and self.whole_mentions and (
                cmd.get("piped") or any(a.startswith(("<(", ">(")) or "$(" in a or "`" in a for a in args)):
            # A shell, interpreter or `source` reading a PIPE, or given generated text as its program
            # (`printf 'kubectl ...' | bash`, `bash <(echo kubectl ...)`, `source <(...)`), runs text the hook
            # cannot place.
            raise Refusal("H03")
        if base in SHELLS:
            return self._shell(args, cmd, depth)
        if base == "eval":
            return self.check_text(" ".join(args), depth + 1)
        if base in ("source", "."):
            return
        if INTERPRETERS.match(base):
            # Its code (-c/-e or a script), its arguments and its input are all opaque to the hook: a client
            # named in any of them is refused (`python3 -c ...`, `node x.js kubectl get ns`).
            if any(mentions(t) for t in args + cmd["stdin"]):
                raise Refusal("H03")
            return
        if base in OPAQUE:
            if any(mentions(t) for t in args + cmd["stdin"]):
                raise Refusal("H03")
            return
        if base in GLOBAL_MUTATORS:
            raise Refusal("H06", base)
        if base == "gcloud" and {"container", "clusters", "get-credentials"} <= set(args):
            raise Refusal("H06", "gcloud")
        if base in LOCAL_ONLY:
            return
        if base in KUBE_RUN_NAMES:
            return self._kube_run(w, args, prefixed=bool(env) or wrapped)
        fam = FAMILY.get(base)
        if fam is None:
            # Any other command. A data-only command (echo, grep, cat, git, ...) may carry a client's name as text.
            # Every other command naming a client, in an argument, a redirect target or its input, is a position
            # the hook does not understand, so it is refused (H15): only understood positions are allowed.
            data = base in DATA_OPTIONS and options_in_table(args, DATA_OPTIONS[base])
            targets = cmd.get("redirect_targets", [])
            if any(t.startswith((">(", "<(")) for t in targets):
                data = False     # a redirection into a process substitution feeds another program
            if not data and (any(mentions(t) for t in args + targets + cmd["stdin"]) or mentions(cmd.get("raw", ""))):
                raise Refusal("H15")
            return
        p = parse_flags(args, VALUE_FLAGS[fam])
        kind = classify(fam, p)
        sub = safe_sub(p["pos"][0]) if p["pos"] else "-"
        if kind == "local":
            return
        if kind == "secret-print":
            raise Refusal("H08", base, sub)
        if kind == "config-write":
            vals = p["values"].get("--kubeconfig", [])
            if len(set(vals)) != 1 or not vals[0] or DYNAMIC.search(vals[0]):
                raise Refusal("H06", base, sub)
            kc = os.path.expanduser(vals[0])
            if not os.path.isabs(kc):
                if not self.cwd:
                    raise Refusal("H06", base, sub)
                kc = os.path.join(self.cwd, kc)
            if os.path.realpath(kc) == os.path.realpath(os.path.expanduser("~/.kube/config")):
                raise Refusal("H06", base, sub)
            return
        raise Refusal("H01" if fam == "kubectl" else "H07", base, sub)

    def _kube_run(self, w, args, prefixed):
        path = os.path.expanduser(w)
        if not os.path.isabs(path) or os.path.realpath(path) != self.kube_run:
            raise Refusal("H09", "kube-run")
        if prefixed:
            # An assignment prefix or a wrapper (`PATH=/tmp/bin kube-run`, `env PATH=... kube-run`, `timeout 60
            # kube-run`) can choose the interpreter kube-run's `env python3` shebang runs: refused, not enumerated.
            raise Refusal("H16", "kube-run")
        if self.kube_run_at is None:
            self.kube_run_at = self._top_k
        i = 0
        while i < len(args) and args[i].startswith("--") and args[i] != "--":
            # The same option grammar as kube_run.parse_cli: --timeout takes digits only.
            if i + 1 < len(args) and (args[i] == "--authorization"
                                      or (args[i] == "--timeout" and args[i + 1].isdigit())):
                i += 2
            else:
                raise Refusal("H10", "kube-run")
        if i >= len(args) or not CLUSTER_ID.match(args[i]):
            raise Refusal("H10", "kube-run")
        if i + 1 >= len(args) or args[i + 1] != "--" or i + 2 >= len(args):
            raise Refusal("H10", "kube-run")
        kargs = args[i + 2:]
        verb = next((a for a in kargs if not a.startswith("-")), "")
        if any(a == f or a.startswith(f + "=") or short_cluster_has(a, "s") for a in kargs for f in KUBE_RUN_OVERRIDES):
            raise Refusal("H11", "kube-run", safe_sub(verb))

    def _take_assignments(self, words, env):
        while words and not words[0][1] and ASSIGN.match(words[0][0]):
            name, value = ASSIGN.match(words[0][0]).groups()
            if mentions(value):
                raise Refusal("H04")
            env[name] = value
            self.env_changed = True      # H16: an assignment reaches kube-run's interpreter lookup
            words = words[1:]
        return words

    def _unwrap(self, base, rest, env, depth):
        valued = WRAPPERS[base]
        watch_exec = False
        while rest:
            a = rest[0][0]
            if a == "--":
                rest = rest[1:]
                break
            if base == "command" and a in ("-v", "-V"):
                return None
            if base == "env" and (a in ("-S", "--split-string") or a.startswith("--split-string=")):
                separate = a in ("-S", "--split-string")
                text = (rest[1][0] if len(rest) > 1 else "") if separate else a.partition("=")[2]
                # env splits only S; the words after it keep their boundaries, so they are re-quoted, not joined
                # (`env -S bash -c 'kubectl get secrets'` runs bash with ONE -c argument).
                after = rest[2:] if separate else rest[1:]
                self.check_text(" ".join([text] + [shlex.quote(x[0]) for x in after]), depth + 1)
                return None
            if not a.startswith("-") or a == "-":
                break
            if base == "watch" and a in ("-x", "--exec"):
                watch_exec = True
            if a in valued:
                # The word an option consumes as its value is never a command: if it names a cluster client, the
                # option table is wrong for this use or the value hides the command (`watch -n kubectl ...`), so
                # it is refused rather than skipped. A wrong arity entry then fails closed, not open.
                if len(rest) > 1 and mentions(rest[1][0]):
                    raise Refusal("H03")
                rest = rest[2:]
            elif a in OPTIONAL_VALUE.get(base, set()):
                rest = rest[1:]           # bare: no value, so the next word is the command (or another option)
            elif (a.startswith("--") and "=" in a) or a in WRAPPER_FLAGS.get(base, set()):
                rest = rest[1:]
            else:
                # An option this hook does not know may take the next word as its value, so the command word
                # cannot be placed. Fail closed when a cluster client follows anywhere in the rest.
                if any(mentions(w[0]) for w in rest[1:]):
                    raise Refusal("H03")
                rest = rest[1:]
        if base == "watch" and not watch_exec:
            # watch joins its words with spaces and runs them with `sh -c` unless --exec: that is shell text.
            self.check_text(" ".join(x[0] for x in rest), depth + 1)
            return None
        if base in DURATION_WRAPPERS and rest:
            rest = rest[1:]
        if base in ("env", "sudo", "doas"):
            rest = self._take_assignments(rest, env)
        return rest

    def _shell(self, args, cmd, depth):
        # The -c string is checked when present. Standard input fed to a shell is ALWAYS checked as a program:
        # with -s (or no operand) bash runs it, and its operands are only positional parameters (`bash -s x <<<
        # '...'`); with a script operand, the script may still run it (eval, `. /dev/stdin`). Fail closed.
        # The options are parsed to their end BEFORE the -c string is taken: with -c, the command string is the
        # first operand after the options (`bash -c -- 'x'`, `bash -c -e 'x'`), not the word after -c.
        i, c_mode = 0, False
        while i < len(args):
            a = args[i]
            if a == "--":
                i += 1
                break
            if a in ("-o", "+o", "-O", "+O"):
                i += 2
                continue
            if a.startswith("-") or a.startswith("+"):
                if re.match(r"^-[a-zA-Z]+$", a) and "c" in a[1:]:
                    c_mode = True
                i += 1
                continue
            break
        if c_mode and i < len(args):
            self.check_text(args[i], depth + 1)
        for text in cmd["stdin"]:
            self.check_text(text, depth + 1)


def parse_flags(args, valued):
    pos, values, flags, unknown_at, help_ = [], {}, set(), None, False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        # Help is whatever the LAST occurrence sets: pflag updates the value each time, and cobra shows help only
        # when the final value is true (`get secrets --help --help=false` is an API call).
        if a in ("--help", "-h"):
            help_ = True
        elif a.startswith("--help=") or a.startswith("-h="):
            help_ = a.partition("=")[2] in ("1", "t", "T", "TRUE", "true", "True")
        if a.startswith("--") and "=" in a:
            name, _, v = a.partition("=")
            flags.add(name)
            values.setdefault(name, []).append(v)
        elif a in valued:
            flags.add(a)
            values.setdefault(a, []).append(args[i + 1] if i + 1 < len(args) else "")
            i += 1
        elif a.startswith("-") and a != "-":
            flags.add(a)
            values.setdefault(a, []).append("true")
            if unknown_at is None:
                unknown_at = len(pos)
        else:
            pos.append(a)
        i += 1
    return {"pos": pos, "values": values, "flags": flags, "unknown_at": unknown_at, "help": help_}


def _truthy(p, flag):
    vals = p["values"].get(flag)
    return bool(vals) and vals[-1].lower() in ("true", "1", "t", "")


def _known(p, depth):
    return len(p["pos"]) >= depth and (p["unknown_at"] is None or p["unknown_at"] >= depth)


def classify(fam, p):
    """local | secret-print | config-write | api. Anything the hook cannot place is an API call."""
    if p["help"]:
        return "local"
    pos = p["pos"]
    if not pos:
        return "local" if p["unknown_at"] is None and fam in ("kubectl", "helm", "flux") else "api"
    sub = pos[0] if _known(p, 1) else None
    if fam == "kubectl":
        if sub == "version":
            return "local" if _truthy(p, "--client") else "api"
        if sub in KUBECTL_LOCAL_1:
            return "local"
        if sub == "plugin" and _known(p, 2) and pos[1] == "list":
            return "local"
        if sub == "config":
            if not _known(p, 2):
                return "config-write"
            if pos[1] in KUBECTL_CONFIG_READ:
                if pos[1] == "view" and (_truthy(p, "--raw") or _truthy(p, "--flatten")):
                    return "secret-print"
                return "local"
            return "config-write"
        return "api"
    if fam == "helm":
        if sub == "template":
            # --validate and --dry-run=server contact the cluster; only the client-side forms stay local.
            dry = p["values"].get("--dry-run")
            local_dry = dry is None or dry[-1] in ("true", "client", "none", "false")
            return "api" if _truthy(p, "--validate") or not local_dry else "local"
        return "local" if sub in HELM_LOCAL else "api"
    if fam == "flux":
        if sub == "version":
            return "local" if _truthy(p, "--client") else "api"
        if sub in ("help", "completion", "envsubst"):
            return "local"
        if sub in ("create", "install") and _truthy(p, "--export"):
            return "local"
        if sub == "build" and _known(p, 2) and (pos[1] == "artifact" or _truthy(p, "--dry-run")):
            return "local"
        if sub in FLUX_OCI and _known(p, 2) and pos[1] in ("artifact", "artifacts"):
            return "local"
        return "api"
    if fam == "k9s":
        return "local" if sub in ("version", "info", "help", "completion") else "api"
    if fam == "stern":
        return "local" if _truthy(p, "--version") or sub == "completion" else "api"
    return "api"


def deny(r, kube_run):
    if r.where:
        k, n, (a, b) = r.where
        loc = f"command {k} of {n} (chars {a}-{b}{', inside a nested shell or substitution' if r.nested else ''})"
    else:
        loc = "the hook input"
    msg = (f"kubectl-context-guard (TXE-8039): refused {loc}: client={safe_client(r.client) or '-'} "
           f"subcommand={r.sub or '-'} rule={r.rule} ({RULES[r.rule]}). Values are withheld. Cluster API calls "
           f"go through {kube_run} [--authorization <record>] <cluster-id> -- <kubectl arguments>, which checks "
           "the cluster's identity before contact. Local commands (version --client, help, config "
           "get-contexts/current-context, kustomize) need nothing. Report this refusal verbatim to your "
           "coordinator; do not rephrase the command to get past it.")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": msg}}))


# Long flags only a cluster client takes. A run-time command word followed by one of them is refused (H02), even
# when the verb comes later (`$(printf kube%s ctl) --context prod get secrets`).
CLUSTER_FLAGS = {"--context", "--kubeconfig", "--namespace", "--server", "--cluster", "--user", "--token", "--as",
                 "--as-group", "--as-uid", "--certificate-authority", "--client-certificate", "--client-key",
                 "--tls-server-name", "--insecure-skip-tls-verify", "--kuberc", "--all-namespaces",
                 "--request-timeout", "--kube-context", "--kube-apiserver", "--kube-token", "--kube-as-user",
                 "--kube-as-group", "--kube-ca-file", "--kube-tls-server-name"}
# The same shorthand rule as kube_run.short_cluster_has: letters before the first value-taking option are
# booleans, and the rest is its value.
SHORT_VALUE_LETTERS = set("olfcnpkLvs")
# Short options of a cluster client that take a separate value, skipped to find the first operand.
SHORT_VALUED = {"-n", "-s", "-o", "-l", "-c", "-f", "-v", "-L", "-p", "-k"}


def short_cluster_has(arg, letter):
    if not arg.startswith("-") or arg.startswith("--") or len(arg) < 2:
        return False
    for ch in arg[1:]:
        if ch == letter:
            return True
        if ch in SHORT_VALUE_LETTERS or not ch.isalpha():
            return False
    return False


def first_operand(args):
    """The first argument that is not an option or a short option's value (the would-be verb)."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        i += 2 if args[i] in SHORT_VALUED or args[i] in CLUSTER_FLAGS else 1
    return args[i] if i < len(args) else ""


def command_texts(tool_input):
    """The text of each command-like field of an event the hook does not guard: tool_input.command or
    tool_input.cmd, as a string or an argv list (joined with spaces)."""
    texts = []
    for key in ("command", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, list):
            texts.append(" ".join(str(v) for v in value))
    return texts


def main(argv):
    kube_run = DEFAULT_KUBE_RUN
    if len(argv) >= 2 and argv[0] == "--kube-run":
        kube_run = argv[1]
    kube_run = os.path.realpath(os.path.expanduser(kube_run))
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("not an object")
    except ValueError:
        if mentions(raw):
            deny(Refusal("H13"), kube_run)
        return 0
    tool_input = event.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    command = tool_input.get("command")
    if event.get("tool_name") != "Bash" or not isinstance(command, str):
        # Not the guarded shape. Fail closed on a command-like field that names a client; never guard it.
        if any(mentions(text) for text in command_texts(tool_input)):
            deny(Refusal("H14"), kube_run)
        return 0
    if not command:
        return 0
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None
    try:
        Guard(kube_run, cwd, command).check_top(command)
    except Refusal as r:
        deny(r, kube_run)
    except Exception:  # a bug in the hook: refuse only what could be a cluster call
        if mentions(command):
            deny(Refusal("H13"), kube_run)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
