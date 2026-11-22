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
    arguments carry no target, identity or TLS override (H11). The WHOLE Bash command must then be exactly that
    one simple command: the installed kube-run by its absolute literal path, then literal words only, separated
    by spaces (H16; see literal_word). No other command, separator, keyword, group, subshell, nested shell,
    wrapper, assignment, redirection, here-document, comment, substitution or expansion may appear; quoting is
    decoded without evaluation. Any other shape could choose the interpreter of its `env python3` shebang, so it
    is refused rather than modelled. This is a bounded positive grammar, not proof of a trusted pre-existing
    environment.
    An install starts kube-run through an absolute pinned interpreter in isolated mode; the shebang is for running
    it from source (see the README's installation contract). kube-run repeats every check at run time,
    on the arguments it actually receives. kube-run is read-only, and refuses every mutating, interactive or
    tunnelling verb itself.
  - Local commands need nothing, but ONLY the closed, evidenced forms in LOCAL_FORMS, with their listed options:
    - kubectl: version --client, help on a built-in, completion <shell>, options, plugin list, and config
      current-context|get-contexts|view (not --raw/--flatten, which is H08);
    - helm: version, help on a built-in, completion, env, repo list, template <local chart>, lint <local chart>;
    - flux: version --client, help, completion, build artifact, install --export;
    - `kustomize build <local dir>` with no options.
    Anything else (kubectl kustomize, helm plugin/dependency/package/pull, post-renderers, kustomize plugins and
    Helm integration, flux OCI and other builds, unlisted options) is an API call or H03. kubectx, kubens, gcloud
    get-credentials and config writes to the default kubeconfig are refused (H06).

It fails closed. A client reached through something the hook cannot see into is refused: a command word built
at run time (H02); a client inside python -c, ssh, find -exec, docker and the like (H03); an assignment or
alias whose value is a client (H04); a command or nested shell text it cannot parse, whatever it names (H05);
nesting too deep (H12).
sh/bash/zsh -c, eval, here-documents and here-strings fed to a shell, $(...), backticks and <(...) are parsed
recursively, and wrappers (timeout, env, xargs, watch, sudo, nice, nohup, ...) are unwrapped. A wrapper option
the hook does not know may take a value, so it cannot tell which word is the command: when a cluster client
follows it, the command is refused (H03). xargs completes its command from its input at run time, and inherited
stdin cannot be ruled out, so in a line that names a client EVERY xargs is refused (H03). The one exception is a
client named in the text after it, which keeps a specific refusal (H08) and is otherwise refused as an API call
(H01/H07): xargs can extend its argv, so it is never allowed.

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
# SUB-GRAMMAR INVENTORY (root msg_ed14544cad6a: never classify one grammar by silently treating it as another). The
# text a recognized wrapper or code receiver runs is read in ONE of these ways, and nothing else:
#   - POSIX/Bash shell text, by this file's lexer: sh, bash, zsh, dash and ksh with -c, stdin or a here-document;
#     eval; $(...), backticks and <(...)/>(...); watch's words (it runs sh -c); env -S payloads with no `\` or `$`.
#     zsh, dash and ksh differ from Bash only where the decoded forms over-approximate (dash has no $'...').
#   - REFUSED, because the grammar is not modelled (H03): fish text other than a literal script path
#     (UNMODELLED_SHELLS); an unread env split-string spelling (abbreviation, S in a cluster); an env -S payload with
#     a backslash or `$` (env's own escapes and ${NAME}); every xargs in a client line (it builds argv from input).
#   - OPAQUE, refused when the text names a client (H03/H15, read through mention_forms): interpreters (python,
#     node, perl, ...), OPAQUE executors (ssh, docker, find -exec, ...), and every unclassified command, including
#     the languages inside awk, sed and jq. Their own escapes and run-time construction are the documented limit.
#   - argv passthrough, no grammar: env (without -S), timeout, gtimeout, nice, nohup, sudo, doas, command, exec,
#     builtin, time, stdbuf, caffeinate, unbuffer (WRAPPERS, closed option tables), and k3s/microk8s/minikube
#     before kubectl (VENDOR_WRAPPERS). EXCEPT sudo/doas shell modes (SHELL_MODE_OPTIONS: -s, -i, --shell,
#     --login), which are code receivers and are refused in a client-relevant line.
#   In a client-relevant line: EVERY OPAQUE executor is refused (inherited stdin cannot be ruled out), and when the
#   line carries input anywhere, every unclassified non-DATA_OPTIONS command is refused (Guard.line_input).
UNMODELLED_SHELLS = {"fish"}
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
    # (sudo/doas shell modes are flags here, but they are code receivers: see SHELL_MODE_OPTIONS.)
    "watch": {"-t", "--no-title", "-e", "--errexit", "-g", "--chgexit", "-b", "--beep", "-c", "--color", "-x",
              "--exec", "-p", "--precise"},
    "xargs": {"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "--interactive", "-x", "--exit"},
    "timeout": {"--preserve-status", "--foreground", "-v", "--verbose"},
    "gtimeout": {"--preserve-status", "--foreground", "-v", "--verbose"},
}
# wrapper -> its options that start a SHELL (a code receiver: it reads a pipe or stdin when no command follows), not
# argv passthrough. In a client-relevant line they are refused (H03) in _unwrap.
SHELL_MODE_OPTIONS = {"sudo": {"-s", "--shell", "-i", "--login"}, "doas": {"-s"}}
# wrapper -> its options whose value is OPTIONAL and can only be attached (GNU getopt `x::`): the bare form takes
# NO value, so the next word is never consumed (`watch -d 'kubectl get secrets'` runs the quoted command). An
# attached short form (`-d1`, `-ifoo`) is not modelled and is treated as unknown (fail closed); `--long=value`
# takes nothing from the next word.
OPTIONAL_VALUE = {
    "watch": {"-d", "--differences"},
    "xargs": {"-i", "--replace", "-e", "--eof", "-l", "--max-lines"},
}
DURATION_WRAPPERS = {"timeout", "gtimeout"}
# The closed shell-option grammar used in a client-relevant line (inline_program). Bash's single-letter
# invocation options; -o/+o and -O/+O take the next word. Long options take no value; --rcfile and --init-file
# (an opaque startup file) and every other long option are refused there.
SHELL_SHORT_FLAGS = set("abefhkmnptuvxBCEHPTcsilr")
SHELL_SHORT_VALUED = set("oO")
SHELL_LONG_FLAGS = {"--norc", "--noprofile", "--login", "--posix", "--verbose", "--restricted", "--noediting",
                    "--debugger", "--protected"}
INPUT_REDIRECTS = {"<", "<>", "<&"}
# H16, THE KUBE-RUN EXCEPTION'S GRAMMAR. A Bash command that relies on the kube-run exception (one in which the
# installed kube-run is accepted, at any depth) must be EXACTLY ONE simple command:
#   <installed kube-run, absolute and literal> <literal word> ...
# and nothing else. Words are separated by spaces or tabs, with nothing before the first word or after the last.
# There is no other command or separator (; && || | & newline), no keyword, group or subshell, no wrapper or
# prefix assignment, no redirection or here-document, and no comment. Every word is LITERAL (literal_word):
#   - unquoted characters must not be any of  $ ` \ * ? [ ] ~ { } ! # ( ) < > ; & | ' " (an expansion, a
#     pattern, an escape, or an operator) unless inside quotes;
#   - '...' is literal as is;
#   - "..." is literal when it holds no $ ` \ or !.
# So no substitution, parameter or arithmetic expansion, glob, brace or tilde expansion, escape or ANSI-C quoting
# survives, and quoting is decoded without evaluation. Anything else is refused (H16), whatever it seems to do:
# the hook does not claim to know which other shell syntax leaves kube-run's environment alone.
LITERAL_UNQUOTED_FORBIDDEN = set("$`\\*?[]~{}!#()<>;&|")
LITERAL_DQUOTE_FORBIDDEN = set("$`\\!")


def literal_word(raw):
    """True when the word's source text is a literal: decodable by quote removal alone, with no evaluation."""
    i, n = 0, len(raw)
    if n == 0:
        return False
    while i < n:
        c = raw[i]
        if c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                return False
            i = j + 1
        elif c == '"':
            j = raw.find('"', i + 1)
            if j < 0 or any(ch in LITERAL_DQUOTE_FORBIDDEN for ch in raw[i + 1:j]):
                return False
            i = j + 1
        elif c in LITERAL_UNQUOTED_FORBIDDEN or c.isspace():
            return False
        else:
            i += 1
    return True


# An assignment-shaped kube-run argument with a shell-environment-style (upper-case) name. Under an inherited
# keyword mode (`set -k` via an exported SHELLOPTS) bash would move it into kube-run's environment.
ENV_STYLE_ASSIGN = re.compile(r"^[A-Z_][A-Z0-9_]*(?:\[[^\]]*\])?\+?=")
# An assignment word: NAME=v, NAME+=v, NAME[i]=v and NAME[i]+=v.
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=(.*)$", re.S)
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
    "H16": "a command that uses kube-run must be exactly one bare kube-run invocation with literal arguments (no "
           "other command, wrapper, assignment, redirection, expansion or nested shell), because anything else "
           "could choose its interpreter; run kube-run alone, by its absolute path, in its own tool call",
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
                # A quoted delimiter makes the body literal (no expansion); an unquoted one expands it.
                toks.append(("hd", len(bodies), bool(m.group(1)) or bool(re.search(r"[\\'\"]", m.group(2)))))
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
                skip_next = op            # the next word is this redirection's target
            elif op == "<<<":
                herestr = True
            continue
        if t[0] == "hd":
            cur["stdin"].append(bodies[t[1]])
            cur.setdefault("stdin_literal", []).append(t[2])      # a quoted delimiter: a literal body
            continue
        if skip_next:
            cur.setdefault("redirect_targets", []).append(t[1])
            cur.setdefault("redirects", []).append((skip_next, t[1]))     # (operator, target)
            skip_next = False
            continue
        if herestr:
            herestr = False
            cur["stdin"].append(t[1])
            cur.setdefault("stdin_literal", []).append(literal_word(s[t[3]:t[4]]))
            continue
        cur["words"].append((t[1], t[2], t[3], t[4]))
    cmds.append(cur)
    for c in cmds:
        # The command's own source text, quotes included: a client named inside an attached option value
        # (`-O'kubectl get ns'`) has no word boundary in the unquoted word, but does in the source.
        ws = c["words"]
        c["raw"] = s[ws[0][2]:ws[-1][3]] if ws else ""
        c["src"] = s                      # the text the word positions index, for per-word literal checks
    # A simple command is kept whenever it has ANY execution-bearing channel: words, stdin (here-documents and
    # here-strings) or redirection targets (connector review of 24dadc0f: `> "$(kubectl get secrets)"` has no
    # words, but Bash runs the substitution in its target). check_cmd then inspects every channel's
    # substitutions. Only a command with none of the three is empty. Effect: a redirection-only command counts as a
    # command, so H16's single-command rule (single_kube_run) counts it too (`kube-run ...; > f` is two commands).
    return [c for c in cmds if c["words"] or c["stdin"] or c.get("redirect_targets")]


def has_input_channel(cmd):
    """True when a simple command reads input: a pipe, a here-document or here-string, or an input redirection."""
    return bool(cmd.get("piped") or cmd["stdin"] or any(op in INPUT_REDIRECTS for op, _ in cmd.get("redirects", [])))


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


# Quote removal for the mention check (connector review of 77f1bac3: `echo kube''ctl get secrets | bash` ran
# kubectl downstream, because the line-level check read only the raw text). ANSI-C quoting is decoded by Bash at
# parse time, without evaluation, so it is decoded here too.
ANSI_C = re.compile(r"\$'((?:\\.|[^'\\])*)'", re.S)
ANSI_C_ESCAPE = re.compile(r"\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|c(.)|(.))",
                           re.S)
ANSI_C_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
                 "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(body, nul_ends=False):
    """The text Bash makes of the body of $'...' (bash(1), QUOTING). nul_ends=True applies Bash's C-string rule: the
    quoted string ends at its first decoded NUL (\\0, \\x00, \\u0000, \\c@ and the rest), so
    `$'kubectl\\0ignored'` is `kubectl` (connector review of ad2765b4)."""
    if nul_ends:
        decoded = _ansi_c(body)
        return decoded.split("\0", 1)[0]
    def one(m):
        octal, hx, u4, u8, ctl, other = m.groups()
        try:
            if octal:
                return chr(int(octal, 8) & 0xFF)
            if hx or u4 or u8:
                return chr(int(hx or u4 or u8, 16))
        except (ValueError, OverflowError):
            return ""
        if ctl is not None:
            return chr(ord(ctl) & 0x1F)
        other = other or ""
        return ANSI_C_SIMPLE.get(other, "\\" + other)
    return ANSI_C_ESCAPE.sub(one, body)


# BRACE EXPANSION for the mention check (root msg_205b648bd468). Bash expands `kube{ctl,x}` to `kubectl kubex`
# before it runs anything, with no variable and no file involved, so a name can be assembled from deterministic
# brace alternatives. The words are expanded structurally: deleting braces and commas would give `kubectlx` and
# hide the alternative. The expansion is BOUNDED and fails closed: a word with more than BRACE_WORD_BUDGET
# expansions, a text with more than BRACE_TEXT_BUDGET in all or more than BRACE_CHAR_BUDGET expanded
# characters, nesting deeper than BRACE_MAX_DEPTH, or a sequence it cannot bound counts as naming a client
# (BraceOverBudget). Nothing is expanded past the budget: the word count AND the expanded length are computed from
# the parsed groups first (_brace_cost), and only a word within every budget is built.
BRACE_WORD_BUDGET = 256
BRACE_TEXT_BUDGET = 4096
BRACE_CHAR_BUDGET = 1 << 20
BRACE_MAX_DEPTH = 16
# Units examined by sequence checks in one text. A literal group (no comma) is not recursed into, but its inner
# units are read as a possible sequence, so deeply nested literal braces would cost the square of their length.
BRACE_WORK_BUDGET = 1 << 20
# Characters that end a word for brace expansion: blanks, operators, and the delimiters of a substitution, whose
# inner text holds words of its own.
BRACE_BREAK = set(" \t\r\n;|&<>()`")
# {x..y[..incr]}: integers, or single characters. A mixed or other form is literal in Bash; reading it as a
# character sequence only adds forms.
BRACE_NUMERIC_SEQ = re.compile(r"([-+]?\d+)\.\.([-+]?\d+)(?:\.\.([-+]?\d+))?")
BRACE_CHAR_SEQ = re.compile(r"(\S)\.\.(\S)(?:\.\.([-+]?\d+))?")
# A numeric sequence contributes only digits and signs. No client name holds two adjacent digits, so a member
# other than a single unpadded digit stands as this sentinel, which can be part of no name.
BRACE_NUMERIC_OTHER = "00"


class BraceOverBudget(Exception):
    pass


def _brace_words(text):
    """The text as ("sep", char) and ("word", units) items for brace expansion. A unit is one unquoted character,
    or a whole quoted string, escape or ${...} with its quoting kept, so only an UNQUOTED `{`, `,` or `}` is a
    one-character unit (Bash does not expand quoted or escaped braces, nor ${...})."""
    items, word, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if c in BRACE_BREAK:
            if word:
                items.append(("word", word))
                word = []
            items.append(("sep", c))
            i += 1
        elif c == "\\":
            word.append(text[i:i + 2])
            i += 2
        elif c == "'" or text.startswith("$'", i):
            ansi = c == "$"
            j = i + (2 if ansi else 1)
            while j < n and text[j] != "'":
                j += 2 if ansi and text[j] == "\\" else 1
            word.append(text[i:j + 1])
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            word.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("${", i):
            j, d = i + 2, 1
            while j < n and d:
                d += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            word.append(text[i:j])
            i = j
        else:
            word.append(c)
            i += 1
    if word:
        items.append(("word", word))
    return items


def _brace_sequence(inner):
    """The members of a sequence expression {x..y[..incr]} as alternatives, or None when it is not one."""
    if not inner or any(len(u) != 1 for u in inner):
        return None
    s = "".join(inner)
    try:
        m = BRACE_NUMERIC_SEQ.fullmatch(s)
        if m:
            a, b = int(m[1]), int(m[2])
            step = abs(int(m[3])) if m[3] else 1
            step = step or 1
            lo, hi = min(a, b), max(a, b)
            padded = any(re.match(r"[-+]?0\d", x) for x in (m[1], m[2]))
            singles = [] if padded else [str(d) for d in range(10) if lo <= d <= hi and (d - a) % step == 0]
            return singles + ([BRACE_NUMERIC_OTHER] if (hi - lo) // step + 1 > len(singles) else [])
        m = BRACE_CHAR_SEQ.fullmatch(s)
        if m:
            a, b = ord(m[1]), ord(m[2])
            step = abs(int(m[3])) if m[3] else 1
            step = step or 1
            lo, hi = min(a, b), max(a, b)
            if (hi - lo) // step + 1 > BRACE_WORD_BUDGET:
                raise BraceOverBudget
            return [chr(c) for c in range(lo, hi + 1) if (c - a) % step == 0]
    except ValueError:            # an integer too long to convert: not bounded here
        raise BraceOverBudget
    return None


def _brace_parse(units, lo, hi, match, commas, depth, work):
    """units[lo:hi] as nodes: a str is literal, a list holds the alternatives (each a node list) of one group."""
    if depth > BRACE_MAX_DEPTH:
        raise BraceOverBudget
    out, lit, i = [], [], lo

    def group(node):
        if lit:                   # adjacent literal units become ONE string, so expansion copies runs, not chars
            out.append("".join(lit))
            lit.clear()
        out.append(node)

    while i < hi:
        j = match.get(i) if units[i] == "{" else None
        if j is not None and j < hi:
            if commas[i]:
                bounds = [i] + commas[i] + [j]
                group([_brace_parse(units, a + 1, b, match, commas, depth + 1, work) for a, b in zip(bounds, bounds[1:])])
                i = j + 1
                continue
            work[0] += j - i
            if work[0] > BRACE_WORK_BUDGET:
                raise BraceOverBudget
            seq = _brace_sequence(units[i + 1:j])
            if seq is not None:
                group([[v] for v in seq])
                i = j + 1
                continue
        lit.append(units[i])      # literal, including a `{` that opens no group; groups inside it still expand
        i += 1
    if lit:
        out.append("".join(lit))
    return out


def _brace_cost(nodes, cap_words, cap_chars):
    """(words, characters) the nodes expand to, COMPUTED WITHOUT EXPANDING (root's r29 review: the byte bound must
    hold before anything is built). A prefix set of W words and C characters followed by a group whose alternatives
    total w words and c characters gives W*w words and C*w + W*c characters. Past either cap it returns
    (cap_words + 1, cap_chars + 1) at once."""
    over = (cap_words + 1, cap_chars + 1)
    words, chars = 1, 0
    for x in nodes:
        if isinstance(x, str):
            chars += words * len(x)
        else:
            w = c = 0
            for alt in x:
                aw, ac = _brace_cost(alt, cap_words, cap_chars)
                w, c = w + aw, c + ac
                if w > cap_words or c > cap_chars:
                    return over
            words, chars = words * w, chars * w + words * c
        if words > cap_words or chars > cap_chars:
            return over
    return words, chars


def _brace_expand(nodes):
    """Called only after _brace_cost has bounded the result. Every alternative yields at least one word, so no
    partial list is larger than the result; each alternative is expanded once."""
    outs = [""]
    for x in nodes:
        if isinstance(x, str):
            outs = [o + x for o in outs]
        else:
            alts = [e for alt in x for e in _brace_expand(alt)]
            outs = [o + e for o in outs for e in alts]
    return outs


def brace_expanded(text):
    """The text with each brace-expanded word replaced by its expansions, separated by spaces, or None when no word
    expands. Bash's matching: a `{` opens a group at its matching unquoted `}` when it has a top-level comma or is a
    sequence expression; otherwise it is literal and scanning goes on inside it. Raises BraceOverBudget past a
    bound (see BRACE_WORD_BUDGET)."""
    if "{" not in text:
        return None
    out, total, chars, changed, work = [], 0, 0, False, [0]
    for kind, val in _brace_words(text):
        if kind == "sep" or "{" not in val:
            out.append(val if kind == "sep" else "".join(val))
            continue
        match, commas, stack = {}, {}, []
        for k, u in enumerate(val):           # one pass: Bash's nesting count, and each group's top-level commas
            if u == "{":
                stack.append(k)
                commas[k] = []
            elif u == "}" and stack:
                match[stack.pop()] = k
            elif u == "," and stack:
                commas[stack[-1]].append(k)
        nodes = _brace_parse(val, 0, len(val), match, commas, 0, work)
        if all(isinstance(x, str) for x in nodes):
            out.append("".join(val))
            continue
        # Preflight: the word count and the expanded length (plus one separator per word) are checked against every
        # budget BEFORE _brace_expand builds a single string.
        count, length = _brace_cost(nodes, BRACE_WORD_BUDGET, BRACE_CHAR_BUDGET - chars)
        total += count
        chars += length + count
        if count > BRACE_WORD_BUDGET or total > BRACE_TEXT_BUDGET or chars > BRACE_CHAR_BUDGET:
            raise BraceOverBudget
        out.append(" ".join(_brace_expand(nodes)))
        changed = True
    return "".join(out) if changed else None


def _strip_quotes(text):
    return re.sub(r"[\\'\"]", "", text)


def mention_forms(text):
    """The forms of a text the mention check reads. It parses no command structure, so it also covers text the lexer
    cannot read (a here-document body, a raw JSON event), and each form only ADDS matches:
      - the text itself;
      - the text with backslashes removed (`kube\\ctl` runs kubectl);
      - QUOTE-DECODED: line continuations removed, then every quote character and backslash removed, so quote
        removal cannot split a name (`kube''ctl`, `kube"c"tl`, `'kube'ctl`, `kube$""ctl`);
      - the same after every $'...' is ANSI-C decoded (`$'\\x6bubectl'`, `kube$'\\x63'tl`), once as decoded and
        once with each quoted segment ended at its first decoded NUL, as Bash does (`$'kubectl\\0ignored'`);
      - BRACE-EXPANDED (brace_expanded): each of those bases with its brace words expanded, first honouring the
        quotes (Bash's own order: braces, then quote removal), then once more with the quotes already removed, so
        braces inside a quoted string that a nested shell later reads (`bash -c 'echo kube{ctl,x} | bash'`)
        count too.
    Deleting every quote over-approximates quote removal: a quote that is itself data (`"it's"`) joins the text
    around it too. That direction can only refuse more. Raises BraceOverBudget past a brace bound."""
    forms = [text]
    if "\\" in text:
        forms.append(text.replace("\\", ""))
    quoted = any(c in text for c in "'\"\\")
    # $"..." is locale quoting: with no translation it is "...", so its `$` goes too.
    joined = text.replace("\\\r\n", "").replace("\\\n", "").replace('$"', '"') if quoted else text
    bases = [joined]
    if "$'" in joined:
        bases.append(ANSI_C.sub(lambda m: _ansi_c(m.group(1)), joined))
        # And with each quoted segment ended at its first decoded NUL, as Bash does (`$'kube\0x'$'ctl'` is
        # `kubectl`). The untruncated form above is kept, so the forms stay a superset.
        bases.append(ANSI_C.sub(lambda m: _ansi_c(m.group(1), nul_ends=True), joined))
    for base in bases:
        stripped = _strip_quotes(base) if quoted else base
        if quoted:
            forms.append(stripped)
        if "{" in base:
            expanded = brace_expanded(base)
            if expanded is not None:
                forms.append(_strip_quotes(expanded))
            if quoted:
                expanded = brace_expanded(stripped)
                if expanded is not None:
                    forms.append(expanded)
    return forms


def mentions(text):
    """True when any form of the text (mention_forms) names a cluster client, or when its brace expansion is over a
    bound (fail closed). A superset of the raw-text check, so every caller refuses at least what it refused
    before."""
    try:
        forms = mention_forms(text)
    except BraceOverBudget:
        return True
    return any(MENTION.search(t) or MENTION_ATTACHED.search(t) for t in forms)


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
        # Read through mention_forms: a name split by quote removal (`echo kube''ctl ... | bash`) still marks the
        # line client-relevant, so pipe receivers and code-running commands are inspected (H03).
        self.whole_mentions = mentions(whole)
        # H16: the top-level command index of the first installed kube-run invocation the hook accepted, at any
        # depth. When it is set, the whole command must match the kube-run exception's grammar (single_kube_run).
        self.kube_run_at = None
        self._top_k = 0
        # INPUT-BEARING LINE (root msg_5bee06ed72f4): True once any simple command of the line (or of a nested text)
        # reads a pipe, an input redirection, a here-document or a here-string. Grouping (`( ... )`, `{ ...; }`,
        # loop bodies, `done < f`) lets a later command inherit that input without carrying the flag itself, so
        # the receiver rules below use this line-wide fact rather than each simple command's own flags.
        self.line_input = False

    # Top level: locate a refusal by simple-command index and character span.
    def check_top(self, text):
        try:
            cmds = simple_commands(text)
        except ParseError:
            # A command the hook cannot parse is ambiguous: refused whether or not its raw text names a client,
            # because bash may unquote what the text hides (`kube\ctl ... <<\EOF`).
            raise Refusal("H05")
        self.line_input = self.line_input or any(has_input_channel(c) for c in cmds)
        for k, cmd in enumerate(cmds, 1):
            self._top_k = k
            try:
                self.check_cmd(cmd, 0)
            except Refusal as r:
                ws = cmd["words"]
                span = (ws[0][2], ws[-1][3]) if ws else (0, 0)
                r.where = (k, len(cmds), span)
                raise
        if self.kube_run_at is not None and not self.single_kube_run(text, cmds):
            # The kube-run exception holds only for ONE bare, literal kube-run invocation: any other shape (another
            # command, a wrapper, an assignment, a redirection, an expansion, a nested shell) is refused.
            r = Refusal("H16", "kube-run")
            ws = cmds[self.kube_run_at - 1]["words"]
            r.where = (self.kube_run_at, len(cmds), (ws[0][2], ws[-1][3]) if ws else (0, 0))
            raise r

    def single_kube_run(self, text, cmds):
        """The kube-run exception's grammar (see LITERAL_UNQUOTED_FORBIDDEN): the whole text is exactly one simple
        command whose first word is the installed kube-run, every word literal, separated by spaces or tabs only."""
        if len(cmds) != 1:
            return False
        cmd = cmds[0]
        ws = cmd["words"]
        if not ws or cmd["stdin"] or cmd.get("redirect_targets") or cmd.get("piped"):
            return False
        if text.strip(" \t") != text[ws[0][2]:ws[-1][3]]:
            return False                  # something before the first word or after the last (a comment, `&`)
        for a, b in zip(ws, ws[1:]):
            gap = text[a[3]:b[2]]
            if not gap or gap.strip(" \t"):
                return False              # an operator, a redirection or a newline between words
        if not all(literal_word(text[w[2]:w[3]]) for w in ws):
            return False
        first = ws[0][0]
        return os.path.isabs(first) and os.path.realpath(first) == self.kube_run

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
        self.line_input = self.line_input or any(has_input_channel(c) for c in cmds)
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
        # Words keep their source positions (text, flags, start, end) where the lexer gave them, for literal checks.
        words = list(cmd["words"])
        env = {}
        while words and words[0][0] in KEYWORDS:
            words.pop(0)
        words = self._take_assignments(words, env)
        # XARGS IS AN INPUT CONSUMER, not a transparent wrapper (connector security review of 13864551; root
        # msg_04775a3d3836): `printf 'kubectl delete secrets -A' | xargs env` runs `env kubectl delete secrets -A`, a
        # command completed at run time from xargs's input. In a client-relevant line EVERY xargs counts as having
        # input, because inherited stdin cannot be ruled out (`... | ( xargs env )`, `... | while read; do xargs env;
        # done`, `( xargs env ) < f`). Such an xargs is refused (H03) whatever it runs, except a cluster client
        # named in the text. That client keeps a specific refusal (H08), and is otherwise refused as an API call
        # (H01/H07), never allowed, because xargs can extend its argv.
        xargs_input = False
        while words:
            w, fl = words[0][0], words[0][1]
            if xargs_input and self.whole_mentions and (w == "[" or "ansi" in fl or DYNAMIC.search(w)):
                raise Refusal("H03")      # `... | xargs [`, `... | xargs $X`: not a client named in the text
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
                if base == "xargs" and self.whole_mentions:
                    xargs_input = True
                words = self._unwrap(base, words[1:], env, depth)
                if words is None:
                    if xargs_input and self.whole_mentions:
                        raise Refusal("H03")  # `... | xargs watch`, `... | xargs env -S`: completed from the input
                    return
                continue
            if base in VENDOR_WRAPPERS and len(words) > 1 and os.path.basename(words[1][0]) == "kubectl":
                rest = words[2:]
                words = [("kubectl", set())] + (rest[1:] if rest and rest[0][0] == "--" else rest)
                continue
            break
        if xargs_input and self.whole_mentions and (not words or os.path.basename(words[0][0]) not in FAMILY):
            # Bare `xargs` runs echo; `xargs env`, `xargs sh -c`, `xargs -I{} {}`, `xargs echo`: all completed from
            # the input. Conservative by design: `printf kubectl | xargs echo` is refused too.
            raise Refusal("H03")
        if not words:
            for stdin in cmd["stdin"]:
                if mentions(stdin):
                    raise Refusal("H03")
            return
        w = words[0][0]
        base = os.path.basename(w)
        args = [x[0] for x in words[1:]]
        if base in UNMODELLED_SHELLS:
            # fish's grammar is not the POSIX shell's this lexer reads (`\x63` and `\u` escapes outside quotes,
            # `(cmd)` substitution without `$`, different quoting), so text it would run is refused (H03), whatever
            # it seems to name. ONLY a plain script file is accepted (opaque, as for every shell): one or more
            # LITERAL words (literal_word on their source: no substitution, process substitution, expansion or
            # option), and no pipe, stdin or input redirection. `fish <(printf ...)` (plugin review of fc305d8f),
            # `fish $(...)`, `fish "$S"` and a bare `fish` (it reads stdin) are refused.
            src, operands = cmd.get("src", ""), words[1:]
            literal_script = bool(operands) and all(
                len(x) >= 4 and not x[0].startswith("-") and literal_word(src[x[2]:x[3]]) for x in operands)
            if (not literal_script or cmd.get("piped") or cmd["stdin"]
                    or any(op in INPUT_REDIRECTS for op, _ in cmd.get("redirects", []))):
                raise Refusal("H03")
        runs_text = base in SHELLS or base in ("eval", "source", ".") or bool(INTERPRETERS.match(base))
        if runs_text and self.whole_mentions and (
                cmd.get("piped") or any(a.startswith(("<(", ">(")) or "$(" in a or "`" in a for a in args)):
            # A shell, interpreter or `source` reading a PIPE, or given generated text as its program
            # (`printf 'kubectl ...' | bash`, `bash <(echo kubectl ...)`, `source <(...)`), runs text the hook
            # cannot place.
            raise Refusal("H03")
        kind = ("shell" if base in SHELLS else "eval" if base == "eval" else "source" if base in ("source", ".")
                else "interpreter" if INTERPRETERS.match(base) else None)
        if kind and self.whole_mentions:
            # A client-relevant line: the code-running command must have exactly one inline program channel.
            return self.check_text(self.inline_program(kind, cmd, words), depth + 1)
        if base in SHELLS:
            return self._shell(args, cmd, depth)
        if base == "eval":
            return self.check_text(" ".join(args), depth + 1)
        if base in ("source", "."):
            return
        if INTERPRETERS.match(base):
            # Its code (-c/-e or a script), its arguments and its input are all opaque to the hook: a client
            # named in any of them is refused (`python3 -c ...`, `node x.js kubectl get ns`).
            if any(mentions(t) for t in args + cmd["stdin"] + cmd.get("redirect_targets", [])):
                raise Refusal("H03")
            return
        if base in OPAQUE:
            # Every input channel counts, redirection targets included (filter audit after 24dadc0f:
            # `ssh host < <(echo kubectl get secrets)` feeds the process substitution's text to the remote shell).
            if any(mentions(t) for t in args + cmd["stdin"] + cmd.get("redirect_targets", [])):
                raise Refusal("H03")
            # An opaque executor runs input the hook cannot place: its pipe, an input redirection, or stdin it
            # INHERITS through a subshell, group or loop body (connector review of b0e344e3, `echo 'kubectl get
            # secrets' | su -s /bin/bash root`; plugin review of a3f9e20f, `... | ( ssh host )`). Its own
            # simple-command flags cannot rule that out, so in a client-relevant line EVERY opaque executor is
            # refused (H03), as every xargs is (root msg_5bee06ed72f4).
            if self.whole_mentions:
                raise Refusal("H03")
            return
        if base in GLOBAL_MUTATORS:
            raise Refusal("H06", base)
        if base == "gcloud" and {"container", "clusters", "get-credentials"} <= set(args):
            raise Refusal("H06", "gcloud")
        if base in LOCAL_ONLY:
            # kustomize: ONLY `kustomize build <local dir>` with no options. Its plugin, KRM-function, exec and
            # Helm integrations (--enable-alpha-plugins, --enable-exec, --enable-helm, --helm-command) and a
            # git-URL directory can run other programs, and its reference page documents no flags to evidence.
            if not (len(args) == 2 and args[0] == "build" and kustomize_local_path(args[1])):
                raise Refusal("H03")
            return
        if base in KUBE_RUN_NAMES:
            return self._kube_run(w, args)
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
            if not data and self.whole_mentions and self.line_input:
                # An unclassified command may be a code receiver the hook does not list (`busybox sh`, `ash`, `pwsh`,
                # a versioned `bash5.2`), and in a line that carries input it may read that input, directly or by
                # inheritance through a group or loop (root msg_5bee06ed72f4). Fail closed: in a client-relevant,
                # input-bearing line, only the DATA_OPTIONS set (with its listed options) and classified commands
                # may run. Every other command is refused (H03), wherever it sits in the line.
                raise Refusal("H03")
            return
        p = parse_flags(args, VALUE_FLAGS[fam])
        kind = classify(fam, p)
        sub = safe_sub(p["pos"][0]) if p["pos"] else "-"
        if xargs_input and kind != "secret-print":
            # Run by an xargs, which can append its input to these arguments: whatever kind the visible argv has
            # (local, config-write, api), the effective argv is not known, so it is refused as an API call. A
            # specific refusal (H08) is kept.
            raise Refusal("H01" if fam == "kubectl" else "H07", base, sub)
        if kind == "local" and not local_form(base, args, p):
            kind = "api"      # not one of the closed, evidenced LOCAL_FORMS: an API call (H01/H07)
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

    def _kube_run(self, w, args):
        path = os.path.expanduser(w)
        if not os.path.isabs(path) or os.path.realpath(path) != self.kube_run:
            raise Refusal("H09", "kube-run")
        if any(ENV_STYLE_ASSIGN.match(a) for a in args):
            # Defence in depth against an inherited keyword mode: `kube-run c -- get pods PATH=/tmp/bin`.
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
            name, value = ASSIGN.match(words[0][0]).groups()    # NAME, the value (an index or += dropped)
            if mentions(value):
                raise Refusal("H04")
            env[name] = value
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
            if a in SHELL_MODE_OPTIONS.get(base, ()) and self.whole_mentions:
                # A shell mode is a code receiver, not argv passthrough (connector review of b0e344e3): `sudo -s`
                # and `sudo -i` run the target user's shell, which reads the PIPE or stdin when no command follows
                # (`echo 'kubectl get secrets' | sudo -n -s`). In a client-relevant line it is refused (H03), the
                # same rule as a shell reading a pipe. A cluster holding the letter (`-ns`) is an unknown option and
                # is already refused there.
                raise Refusal("H03")
            if base == "command" and a in ("-v", "-V"):
                return None
            if base == "env" and ((a.startswith("--") and len(a.partition("=")[0]) > 2
                                   and a.partition("=")[0] != "--split-string"
                                   and "--split-string".startswith(a.partition("=")[0]))
                                  or (len(a) > 2 and a[0] == "-" and a[1] not in "-S" and "S" in a[2:])):
                # A split-string payload in a spelling the branch below does not read (plugin review of fc305d8f):
                # a getopt abbreviation (`--sp=...`, `--split ...`; no other GNU env long option starts with
                # `--s`) or S inside a short-option cluster (`-iS'...'`, `-vS ...`). Not modelled, so refused (H03),
                # whatever it names. A cluster whose attached value merely contains an S (`-uSOME`) is refused too.
                raise Refusal("H03")
            if base == "env" and (a in ("-S", "--split-string") or a.startswith("--split-string=")
                                  or (a.startswith("-S") and len(a) > 2)):
                # All three spellings carry a split-string payload: `-S <text>`, `--split-string=<text>`, and the
                # attached `-S<text>` (connector security review of 77689338). Each is checked as shell text.
                separate = a in ("-S", "--split-string")
                if separate:
                    text = rest[1][0] if len(rest) > 1 else ""
                else:
                    text = a.partition("=")[2] if a.startswith("--") else a[2:]
                # env's split-string grammar is NOT the shell's (connector review of 3fd542d9): `\_` separates
                # arguments, `\c` ends the string, `\t` and the other escapes make characters, and `${NAME}` expands
                # a variable, so `env -S 'kubectl\_get\_secrets'` runs `kubectl get secrets`. The hook does not
                # model that grammar, so a payload holding a backslash or a `$` is refused (H03), whatever it
                # seems to name. The check reads the payload as env receives it (after this shell's quote removal).
                # Without them, the payload's words split as in the shell and it is checked as shell text.
                if "\\" in text or "$" in text:
                    raise Refusal("H03")
                # env splits only S; the words after it keep their boundaries, so they are re-quoted, not joined
                # (`env -S bash -c 'kubectl get secrets'` runs bash with ONE -c argument).
                after = rest[2:] if separate else rest[1:]
                self.check_text(" ".join([text] + [shlex.quote(x[0]) for x in after]), depth + 1)
                return None
            if not a.startswith("-") or a == "-":
                break
            if base == "watch" and a in ("-x", "--exec"):
                watch_exec = True
            if a.startswith("--") and "=" in a:
                # CLOSED: `--name=value` is accepted only for a listed value-taking (or optional-value) option, and
                # its attached value is inspected before it is skipped. Any other `--name=...` is unknown, below.
                name, _, val = a.partition("=")
                if name in valued or name in OPTIONAL_VALUE.get(base, set()):
                    if not val or mentions(val):
                        raise Refusal("H03")
                    rest = rest[1:]
                    continue
            if a in valued:
                # The word an option consumes as its value is never a command: if it names a cluster client, the
                # option table is wrong for this use or the value hides the command (`watch -n kubectl ...`), so
                # it is refused rather than skipped. A wrong arity entry then fails closed, not open.
                if len(rest) > 1 and mentions(rest[1][0]):
                    raise Refusal("H03")
                rest = rest[2:]
            elif a in OPTIONAL_VALUE.get(base, set()):
                rest = rest[1:]           # bare: no value, so the next word is the command (or another option)
            elif a in WRAPPER_FLAGS.get(base, set()):
                rest = rest[1:]
            else:
                # An option this hook does not know, an unknown `--name=value`, or an ATTACHED short value
                # (`-uroot`, `-S'...'` on a wrapper that is not env): its arity and payload are not modelled.
                # Closed grammar: refused in a line that names a cluster client, and whenever the word itself (its
                # attached payload) or anything after it names one. Otherwise it is skipped.
                if self.whole_mentions or mentions(a) or any(mentions(w[0]) for w in rest[1:]):
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

    def inline_program(self, kind, cmd, words):
        """The ONE inline program a code-running command runs, in a line that names a cluster client, or H03.

        The shared input-channel classifier for shells, source/., eval and interpreters. The only channels it
        accepts for recursive inspection are a literal `-c` argument (shells), literal eval arguments, and one
        literal here-document (quoted delimiter) or here-string. It refuses (H03):
        - any opaque input: a script, a file or a device operand, an input redirection (`<`, `<>`, `<&`,
          `< <(...)`) or a pipe;
        - `source`/`.` of any file (even `/dev/stdin` with inspected input), and any interpreter (none of their
          program channels is modelled);
        - more than one program channel, no channel at all, or a non-literal one;
        - a shell option outside the closed grammar (see SHELL_SHORT_FLAGS).
        The parser boundary is a limit: a channel this classifier does not know is refused only where it shows
        up as one of the shapes above."""
        if cmd.get("piped") or any(op in INPUT_REDIRECTS for op, _ in cmd.get("redirects", [])):
            raise Refusal("H03")
        if kind in ("source", "interpreter"):
            raise Refusal("H03")
        programs = []
        for body, literal in zip(cmd["stdin"], cmd.get("stdin_literal", [])):
            if not literal:
                raise Refusal("H03")              # an unquoted here-document delimiter expands its body
            programs.append(body)
        if len(cmd.get("stdin_literal", [])) != len(cmd["stdin"]):
            raise Refusal("H03")
        src = cmd.get("src", "")
        args = words[1:]

        def literal(word):
            return len(word) >= 4 and literal_word(src[word[2]:word[3]])

        if kind == "eval":
            if not args or not all(literal(w) for w in args):
                raise Refusal("H03")
            programs.append(" ".join(w[0] for w in args))
        else:                                     # a shell: a CLOSED option grammar
            if any(w[0] == "" for w in args):
                raise Refusal("H03")              # an empty word in the option or operand walk: refused, not indexed
            i, c_mode, s_mode = 0, False, False
            while i < len(args):
                a = args[i][0]
                if a.startswith(("-", "+")) and not literal(args[i]):
                    raise Refusal("H03")          # an option word must be literal: arity is never inferred
                if a == "--" or a == "-":
                    i += 1
                    break
                if a.startswith("--"):
                    # No recognised long option takes a value; --rcfile/--init-file add an opaque startup file.
                    if "=" in a or a not in SHELL_LONG_FLAGS:
                        raise Refusal("H03")
                    i += 1
                    continue
                if a[0] in "-+" and len(a) > 1:
                    letters, i = a[1:], i + 1
                    for k, ch in enumerate(letters):
                        if ch in SHELL_SHORT_VALUED:
                            # -o/+o name and -O/+O shopt take the NEXT word; it must be last in its cluster.
                            # The value must exist, be literal and non-empty, and name no client.
                            if (k != len(letters) - 1 or i >= len(args) or not literal(args[i])
                                    or not args[i][0] or mentions(args[i][0])):
                                raise Refusal("H03")
                            i += 1
                        elif ch in SHELL_SHORT_FLAGS and not (a[0] == "+" and ch in "cs"):
                            c_mode = c_mode or ch == "c"
                            s_mode = s_mode or ch == "s"
                        else:
                            raise Refusal("H03")  # unknown: argument boundaries cannot be established
                    continue
                break
            if c_mode:
                if i >= len(args) or not literal(args[i]):
                    raise Refusal("H03")
                programs.append(args[i][0])       # later words are positional parameters
            elif i < len(args) and not s_mode:
                raise Refusal("H03")              # a script or file operand: opaque
        if len(programs) != 1:
            raise Refusal("H03")
        return programs[0]

    def _shell(self, args, cmd, depth):
        # Used only in a line that names NO client (a client-relevant line goes through inline_program instead).
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


# ---- LOCAL FORMS: a closed, evidenced option grammar per form (TXE-8039, connector review of 24ac0dca) ----
# classify() decides whether a client command is local by its subcommand. A local verdict then stands ONLY if the
# whole argv matches one form below. EVERY option occurrence is checked, before and after the subcommand,
# including repeated flags, `--name=value`, attached short values (`-ojson`, `-o=json`), short clusters and `--`.
# An option outside the form, an unknown or ambiguous arity, or a missing or invalid value makes it "api"
# (refused as H01/H07). Options that name or enable a program (helm --post-renderer/--post-renderer-args,
# --dependency-update; kustomize --enable-*, --helm-command) are in NO form.
# SUPPORTED VERSIONS are the ones the txehq/txe repository pins, and the evidence is their SOURCE at those tags
# (the per-option file:line table is in the README):
# - kubectl v1.34.9: pinned in txe ops/sentry-platform/ci-check.sh and kubernetes/sentry/backups/install_tools.py.
#   Source: kubernetes/kubernetes@v1.34.9 staging/src/k8s.io/kubectl/pkg/cmd/{version/version.go,
#   completion/completion.go, options/options.go, plugin/plugin.go, config/{current_context,get_contexts,view}.go,
#   cmd.go} and staging/src/k8s.io/cli-runtime/pkg/genericclioptions/config_flags.go.
# - helm v4.2.3: pinned in ops/sentry-platform/ci-check.sh. Source: helm/helm@v4.2.3 pkg/cmd/{template,install,lint,
#   repo_list,version,completion,env,root,flags,load_plugins}.go and pkg/cli/environment.go.
# - flux v2.9.4: pinned in .github/workflows/ci.yml and others. The v2.9.5 mention (ops/ci/prod-release.py:2105)
#   is a code comment recording a measurement, not a pin. v2.9.5 is not part of the supported contract.
#   Source: fluxcd/flux2@v2.9.4 cmd/flux/{version,completion,build,build_artifact,install,version_utils,
#   plugin,main}.go.
# - kustomize v5.8.1: pinned in .github/workflows/ci.yml and others. Source:
#   kubernetes-sigs/kustomize@kustomize/v5.8.1 kustomize/commands/build/build.go.
# Helm 3 and any other version are NOT modelled. An installed binary of another version is an unsupported
# install: the hook cannot see which version is installed without executing it, so it does NOT detect or refuse
# an incompatible binary by version. The install prerequisite is not runtime enforcement.
# Only the binaries those pages document get forms: `kubectl`, `helm` and `flux`. oc, kubecolor, k9s, stern
# and microk8s.kubectl have none. Literal client-name detection in values is DEFENCE IN DEPTH only: chart and
# kustomization contents, inherited configuration and installed plugins can still invoke a client, and they are
# deployment prerequisites (README), not something this grammar establishes.
SHELLS_FOR_COMPLETION = {"bash", "zsh", "fish", "powershell"}
# The commands kubectl v1.34.9 registers (staging/src/k8s.io/kubectl/pkg/cmd/cmd.go:380-492). `alpha` is left
# out: it is registered only when it has subcommands (cmd.go:470-486). `create` is left out of the HELP
# built-ins: kubectl dispatches `kubectl create <unknown> ...` to a kubectl-create-* plugin even with --help
# (cmd.go:144-161, IsSubcommandPluginAllowed at cmd.go:172-175).
KUBECTL_BUILTINS = {"annotate", "api-resources", "api-versions", "apply", "attach", "auth", "autoscale", "certificate",
                    "cluster-info", "completion", "config", "cordon", "cp", "create", "debug", "delete", "describe",
                    "diff", "drain", "edit", "events", "exec", "explain", "expose", "get", "kustomize",
                    "label", "logs", "options", "patch", "plugin", "port-forward", "proxy", "replace", "rollout",
                    "run", "scale", "set", "taint", "top", "uncordon", "version", "wait"}
KUBECTL_PLUGIN_SUBCOMMAND_PARENTS = {"create"}
HELM_BUILTINS = {"completion", "create", "dependency", "env", "get", "history", "install", "lint", "list", "package",
                 "plugin", "pull", "push", "registry", "repo", "rollback", "search", "show", "status", "template",
                 "test", "uninstall", "upgrade", "verify", "version"}
# flux v2.9.4 registers plugins as subcommands for every name NOT among its built-ins (cmd/flux/plugin.go:45-60),
# with DisableFlagParsing, so --help reaches a plugin. Only the built-ins whose source was read at v2.9.4
# (version.go, completion.go, build.go, install.go) count as help built-ins.
FLUX_BUILTINS = {"build", "completion", "install", "version"}
BUILTINS = {"kubectl": KUBECTL_BUILTINS, "helm": HELM_BUILTINS, "flux": FLUX_BUILTINS}


def helm_local_path(v):
    return (v == "." or v.startswith(("./", "../", "/"))) and "://" not in v


def kustomize_local_path(v):
    first = v.split("/", 1)[0]
    return (bool(v) and "://" not in v and "?" not in v and "@" not in v and not v.startswith("-")
            and (first in ("", ".", "..") or "." not in first))


B = ("B",)
V = ("V", None)
NOSCHEME = ("V", lambda v: "://" not in v)
K_PATH = ("V", kustomize_local_path)


def choice(*vals, optional=False):
    return ("O" if optional else "V", lambda v: v in vals)


KCFG = {"--kubeconfig": V, "--context": V}
HELM_VALUES = {"--set": V, "--set-json": V, "--set-literal": V, "--set-string": V, "-f": NOSCHEME, "--values": NOSCHEME,
               "--kube-version": V, "--skip-schema-validation": B, "-n": V, "--namespace": V}
LOCAL_FORMS = {
    "kubectl": [
        {"path": ()},
        {"path": ("help",), "ops": (0, 1), "op": lambda o: o in KUBECTL_BUILTINS},
        {"path": ("version",), "opts": {"--client": B, "-o": choice("json", "yaml"), "--output": choice("json", "yaml")},
         "require": ("--client",)},
        {"path": ("completion",), "ops": (1, 1), "op": lambda o: o in SHELLS_FOR_COMPLETION},
        {"path": ("options",)},
        {"path": ("plugin", "list"), "opts": {"--name-only": B}},
        {"path": ("config", "current-context"), "opts": KCFG},
        {"path": ("config", "get-contexts"), "opts": {"--no-headers": B, "-o": choice("name"), "--output": choice("name"),
                                                     **KCFG}, "ops": (0, None)},
        {"path": ("config", "view"), "opts": {"--minify": B, "-o": choice("json", "yaml"),
                                             "--output": choice("json", "yaml"), **KCFG}},
    ],
    "helm": [
        {"path": ()},
        {"path": ("help",), "ops": (0, 1), "op": lambda o: o in HELM_BUILTINS},
        {"path": ("version",), "opts": {"--short": B, "--template": V}},
        {"path": ("completion",), "ops": (1, 1), "op": lambda o: o in SHELLS_FOR_COMPLETION},
        {"path": ("env",)},
        {"path": ("repo", "list"), "opts": {"--no-headers": B, "-o": choice("table", "json", "yaml"),
                                           "--output": choice("table", "json", "yaml")}},
        {"path": ("template",), "ops": (1, 2), "last": helm_local_path,
         "opts": {"-a": V, "--api-versions": V, "--devel": B, "--disable-openapi-validation": B,
                  "--dry-run": choice("client", optional=True), "-g": B, "--generate-name": B, "--include-crds": B,
                  "--is-upgrade": B, "-l": V, "--labels": V, "--name-template": V, "--no-hooks": B, "-s": V,
                  "--show-only": V, "--skip-crds": B, "--skip-tests": B, **HELM_VALUES}},
        {"path": ("lint",), "ops": (0, None), "op": helm_local_path,
         "opts": {"--quiet": B, "--strict": B, "--with-subcharts": B, **HELM_VALUES}},
    ],
    "flux": [
        {"path": ()},
        {"path": ("help",), "ops": (0, 1), "op": lambda o: o in FLUX_BUILTINS},
        {"path": ("version",), "opts": {"--client": B, "-o": choice("json", "yaml"), "--output": choice("json", "yaml")},
         "require": ("--client",)},
        {"path": ("completion",), "ops": (1, 1), "op": lambda o: o in SHELLS_FOR_COMPLETION},
        {"path": ("build", "artifact"), "opts": {"-p": K_PATH, "--path": K_PATH, "-o": K_PATH, "--output": K_PATH,
                                                 "--ignore-paths": V, "--resolve-symlinks": B}},
        {"path": ("install",), "require": ("--export",),
         "opts": {"--export": B, "--components": V, "--components-extra": V, "--cluster-domain": V,
                  "--log-level": choice("debug", "info", "error"), "--network-policy": B, "--watch-all-namespaces": B,
                  "--toleration-keys": V, "--registry": V, "--image-pull-secret": V}},
    ],
}


def _value_ok(spec, v):
    return bool(v) and not mentions(v) and (spec[1] is None or spec[1](v))


def parse_local(args, opts):
    """(positionals, {option: value}) when EVERY option is in opts with a valid value, else None."""
    pos, seen, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos.extend(args[i + 1:])
            break
        if a.startswith("--"):
            name, eq, v = a.partition("=")
            spec = opts.get(name)
            if spec is None:
                return None
            if spec[0] == "B":
                if eq and v.lower() not in ("true", "false"):
                    return None
                seen[name] = "false" if eq and v.lower() == "false" else "true"
            elif not eq and spec[0] == "O":
                seen[name] = "true"                   # an optional value is never taken from the next word
            else:
                if not eq:
                    if i + 1 >= len(args):
                        return None
                    i += 1
                    v = args[i]
                if not _value_ok(spec, v):
                    return None
                seen[name] = v
        elif a.startswith("-") and a != "-":
            k = 1
            while k < len(a):
                name = "-" + a[k]
                spec = opts.get(name)
                if spec is None:
                    return None
                if spec[0] == "B":
                    seen[name] = "true"
                    k += 1
                    continue
                v = a[k + 1:]
                if v.startswith("="):
                    v = v[1:]
                if not v:
                    if spec[0] == "O" or i + 1 >= len(args):
                        return None
                    i += 1
                    v = args[i]
                if not _value_ok(spec, v):
                    return None
                seen[name] = v
                break
        else:
            pos.append(a)
        i += 1
    return pos, seen


def local_form(base, args, p):
    """True when argv is EXACTLY one evidenced local form of this binary (see LOCAL_FORMS)."""
    if any(mentions(a) for a in args):
        raise Refusal("H03")          # defence in depth: a local form whose argument names a client
    if p["help"]:
        # Help is local only for a built-in subcommand of the pinned version: a plugin receives `--help` itself.
        # A kubectl parent that dispatches unknown subcommands to plugins (`create`) is never help-local.
        if base == "kubectl" and p["pos"] and p["pos"][0] in KUBECTL_PLUGIN_SUBCOMMAND_PARENTS:
            return False
        return base in BUILTINS and (not p["pos"] or p["pos"][0] in BUILTINS[base])
    for form in LOCAL_FORMS.get(base, ()):
        parsed = parse_local(args, form.get("opts", {}))
        if parsed is None:
            continue
        pos, seen = parsed
        path = form["path"]
        if tuple(pos[:len(path)]) != path:
            continue
        ops = pos[len(path):]
        lo, hi = form.get("ops", (0, 0))
        if len(ops) < lo or (hi is not None and len(ops) > hi):
            continue
        if "op" in form and not all(form["op"](o) for o in ops):
            continue
        if "last" in form and not (ops and form["last"](ops[-1])):
            continue
        if any(seen.get(f) != "true" for f in form.get("require", ())):
            continue
        return True
    return False


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
           "get-contexts/current-context, kustomize build <local dir>) need nothing. Report this refusal verbatim to your "
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
