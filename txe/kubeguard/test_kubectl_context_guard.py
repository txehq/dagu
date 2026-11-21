# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for kubectl-context-guard.py (TXE-8039). kubeguard_test.go runs this file; directly:
    python3 -I -B test_kubectl_context_guard.py -v       (offline: no cluster, no kubectl, HOME unchanged)

Every case feeds the hook a SYNTHETIC PreToolUse event on stdin and reads its decision. The Claude Code Bash
events follow Claude Code's documented hook input. The other shapes (EventShapes) are hand-written, not
captured from a harness. They show that an unsupported shape fails closed (H14) and is never parsed as
guarded. They show nothing about Codex's real payload, or about a live harness.

PairingWithKubeRun checks the hook against the kube_run.py in this directory, the one it steers calls to:
every kube-run form the hook lets through parses in kube-run, a form kube-run refuses as an override is
refused by the hook too, and the two override lists are the same list.

The data is inert. A TemporaryDirectory holds a fake installed kube-run path (a file never executed) and a
stub bin/ directory, first on the hook's PATH, whose kubectl/helm/flux/kubectx/gcloud/kube-run would record
any execution. The suite asserts that none ran.
"""
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOOK = HERE / "kubectl-context-guard.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KR = _load("kube_run", HERE / "kube_run.py")        # the final kube-run CLI in this tree
GUARD = _load("kubectl_context_guard", HOOK)         # module top level only; main() does not run
PROD_DEFAULT = "gke_project-txe_us-central1_txe-production"
INCIDENT = (
    "kubectl config current-context 2>&1; timeout 30 kubectl get gitrepositories.source.toolkit.fluxcd.io -A "
    "-o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,URL:.spec.url,REV:.status.artifact.revision "
    "2>&1 | head; timeout 30 kubectl get kustomizations.kustomize.toolkit.fluxcd.io -A -o "
    "custom-columns=NS:.metadata.namespace,NAME:.metadata.name,APPLIED:.status.lastAppliedRevision,"
    "READY:.status.conditions[?\\(@.type==\\\"Ready\\\"\\)].status 2>&1 | head -20"
)


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="kubeguard-hook-")
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.ran = self.root / "ran.log"
        for name in ("kubectl", "helm", "flux", "kubectx", "kubens", "gcloud", "k3s", "stern", "k9s", "kube-run"):
            p = self.bin / name
            p.write_text(f"#!/bin/sh\necho {name} >> '{self.ran}'\nexit 97\n")
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
        self.kr = self.root / "installed" / "kube-run"
        self.kr.parent.mkdir()
        self.kr.write_text("# inert stand-in for the installed kube-run; never executed\n")

    def run(self, command, tool="Bash", cwd=None, raw=None, tool_input=None):
        event = {"hook_event_name": "PreToolUse", "tool_name": tool,
                 "tool_input": {"command": command} if tool_input is None else tool_input,
                 "cwd": cwd or str(self.root)}
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        out = subprocess.run([sys.executable, "-I", str(HOOK), "--kube-run", str(self.kr)],
                             input=raw if raw is not None else json.dumps(event), capture_output=True,
                             text=True, env=env, timeout=20)
        assert out.returncode == 0, out.stderr
        assert out.stderr == "", out.stderr
        if not out.stdout.strip():
            return None, ""
        spec = json.loads(out.stdout)["hookSpecificOutput"]
        assert spec["hookEventName"] == "PreToolUse"
        return spec["permissionDecision"], spec["permissionDecisionReason"]


F = None


def setUpModule():
    global F
    F = Fixture()


def tearDownModule():
    assert not F.ran.exists(), "the hook executed a client: " + F.ran.read_text()
    F.tmp.cleanup()


def kr(rest="txe-onprem-ci -- get pods -n arc-runners"):
    return f"{F.kr} {rest}"


# kube-run argument forms shared by the hook cases and PairingWithKubeRun.
ALLOWED_RESTS = ("txe-onprem-ci -- get pods -n arc-runners",
                 "--authorization /x/rec.json txe-onprem-ci -- get pods -n arc-runners",
                 "--timeout 30 txe-onprem-ci -- logs deploy/x -c y",
                 "--timeout 30 --authorization /x/rec.json txe-onprem-ci -- describe pod x",
                 "txe-onprem-ci -- logs pod-a -c app --since 1h")
H10_RESTS = ("txe-onprem-ci get pods", "txe-onprem-ci --", "Bad_Id -- get pods", "-- get pods",
             "--registry /x txe-onprem-ci -- get pods", "$C -- get pods", "--bogus txe-onprem-ci -- get",
             "--timeout x txe-onprem-ci -- get pods", "--timeout txe-onprem-ci -- get pods")
H11_EXTRAS = ("--context txe-prod", "--kubeconfig=/x", "--server https://x", "-s x", "--token=t",
              "--as admin", "--insecure-skip-tls-verify", "--certificate-authority /x", "--kuberc=/x",
              "-shttps://x", "-its")


class Refused(unittest.TestCase):
    def deny(self, cmd, rule=None, client=None, sub=None):
        decision, reason = F.run(cmd)
        self.assertEqual(decision, "deny", cmd)
        if rule:
            self.assertIn(f"rule={rule} ", reason, cmd)
        if client:
            self.assertIn(f"client={client} ", reason, cmd)
        if sub:
            self.assertIn(f"subcommand={sub} ", reason, cmd)
        return reason

    def test_the_incident_command_is_refused_at_its_second_command(self):
        r = self.deny(INCIDENT, "H01", "kubectl", "get")
        self.assertIn("command 2 of ", r)
        self.assertNotIn("gitrepositories", r)

    def test_direct_kubectl_api_calls_are_refused_however_fully_named(self):
        for cmd in ("kubectl get pods", "kubectl get gitrepositories -A", "kubectl version",
                    "kubectl --kubeconfig /x/onprem.yaml get pods", "kubectl --context txe-onprem-ci get pods",
                    "INTENDED_CLUSTER=txe-onprem-ci kubectl --kubeconfig /x/onprem.yaml --context txe-onprem-ci get "
                    "pods", f"kubectl --context {PROD_DEFAULT} get ns", "KUBECONFIG=/x kubectl get pods",
                    "oc get pods", "kubecolor get pods", "kubectl -A get pods", "kubectl api-resources"):
            self.deny(cmd, "H01")

    def test_wrappers(self):
        for cmd in ("timeout 30 kubectl get pods", "gtimeout -s KILL 30 kubectl get pods", "env kubectl get pods",
                    "command kubectl get pods", "exec kubectl get pods", "sudo -u root kubectl get pods",
                    "nohup kubectl get pods", "nice -n 5 kubectl get pods", "time kubectl get pods",
                    "watch -n 5 kubectl get pods", "echo pods | xargs -n 1 kubectl get",
                    "/opt/homebrew/bin/kubectl get pods", "k3s kubectl get pods", "minikube kubectl -- get pods",
                    "if kubectl get ns x; then echo y; fi", "{ kubectl get pods; }", "(kubectl get pods)",
                    "cd /tmp && kubectl get pods", "kubectl config current-context\nkubectl get pods",
                    "kubectl version --client # note\nkubectl get pods", "echo '#'; kubectl get pods"):
            self.deny(cmd, "H01", "kubectl")

    def test_wrapper_options_that_take_a_value_or_are_unknown(self):
        # Connector review of PR 298: `sudo --prompt password kubectl ...` was read as running `password`.
        for cmd in ("sudo --prompt password kubectl get pods", "sudo --prompt=x kubectl get pods",
                    "sudo -E kubectl get pods", "sudo --user root kubectl get pods",
                    "xargs --max-args 1 kubectl get < f", "timeout --preserve-status 30 kubectl get pods"):
            self.deny(cmd, "H01", "kubectl")
        for cmd in ("sudo --frobnicate x kubectl get pods", "env --frob kubectl get pods",
                    "timeout --frob 30 kubectl get pods", "xargs --frob kubectl get", "nice -z kubectl get pods"):
            self.deny(cmd, "H03")

    def test_hidden_command_words(self):
        for cmd in ("$K get pods", '"$KUBECTL" get pods', "${K} get pods", "$(which kubectl) get pods",
                    "`which kubectl` get pods", "$'\\x6bubectl' get pods"):
            self.deny(cmd, "H02")
        # A run-time command word followed by a cluster-only flag, or by a verb after leading options
        # (connector review of 1e1e974c).
        for cmd in ("$(printf kube%s ctl) --context production get secrets -A", '"$K" --kubeconfig /x get pods',
                    "$K -n kube-system get pods", "$K --namespace=x describe pod y", "$K -A get pods"):
            self.deny(cmd, "H02")
        for cmd in ("K=kubectl; $K get pods", "K=/opt/homebrew/bin/kubectl", 'X="kubectl"; $X get ns'):
            self.deny(cmd, "H04")
        self.deny("alias k=kubectl", "H03")

    def test_spellings_the_shell_unquotes(self):
        for cmd in ('kube""ctl get pods', "k\\ubectl get pods", '"kubectl" get pods', "kubectl \\\n  get pods"):
            self.deny(cmd, "H01")

    def test_nested_shells_and_substitutions(self):
        for cmd in ("bash -c 'kubectl get pods'", 'zsh -lc "kubectl get pods"', 'eval "kubectl get pods"',
                    "sh <<'EOF'\nkubectl get pods\nEOF", "bash <<< 'kubectl get pods'", "X=$(kubectl get ns)",
                    'echo "$(kubectl get ns)"', "diff <(kubectl get ns) f", "cat <<EOF\n$(kubectl get ns)\nEOF",
                    "env -S 'kubectl get pods'"):
            r = self.deny(cmd, "H01")
            self.assertIn("nested", r, cmd)

    def test_env_split_string_keeps_the_other_argument_boundaries(self):
        # Connector review of 2ce8d2d2: env splits only S; `bash -c 'kubectl get secrets'` keeps its -c argument.
        for cmd in ("env -S bash -c 'kubectl get secrets'", "env --split-string=bash -c 'kubectl get secrets'",
                    "env -S 'bash -c' 'kubectl get secrets'"):
            r = self.deny(cmd, "H01", "kubectl", "get")
            self.assertIn("nested", r, cmd)

    def test_opaque_executors(self):
        # Inert strings fed to the hook as command text; nothing here is executed (os.system included).
        for cmd in ('python3 -c "import subprocess; subprocess.run([\'kubectl\', \'get\', \'ns\'])"',
                    "python3 - <<'EOF'\nimport os; os.system('kubectl get ns')\nEOF", "ssh host kubectl get pods",
                    "find . -exec kubectl apply -f {} \\;", "docker run --rm bitnami/kubectl:1.31 get pods",
                    "tmux send-keys 'kubectl get pods' Enter"):
            self.deny(cmd, "H03")

    def test_help_is_its_final_value_and_server_side_template_is_an_api_call(self):
        # Connector review of bcca1dcc and 85bde125: help counts only when its LAST value is true, and helm
        # template --dry-run=server may contact the cluster.
        for cmd in ("kubectl get secrets --help --help=false", "kubectl get secrets -h --help=0"):
            self.deny(cmd, "H01", "kubectl", "get")
        for cmd in ("helm template demo ./chart --dry-run=server", "helm template demo ./chart --dry-run=bogus"):
            self.deny(cmd, "H07", "helm", "template")

    def test_other_clients_are_a_compatibility_decision(self):
        for cmd, client in (("helm list -A", "helm"), ("helm upgrade x ./c --kube-context a", "helm"),
                            ("helm template x ./c --validate", "helm"), ("flux get ks -A", "flux"),
                            ("flux reconcile ks x --context a", "flux"), ("flux version", "flux"), ("k9s", "k9s"),
                            ("stern arc", "stern")):
            self.deny(cmd, "H07", client)

    def test_default_kubeconfig_writers_and_credential_prints(self):
        self.deny(f"kubectx {PROD_DEFAULT}", "H06", "kubectx")
        self.deny("kubens arc-runners", "H06", "kubens")
        self.deny("gcloud container clusters get-credentials p --region r", "H06", "gcloud")
        self.deny("kubectl config use-context txe-prod", "H06", "kubectl", "config")
        self.deny("kubectl --kubeconfig ~/.kube/config config use-context x", "H06")
        self.deny('kubectl --kubeconfig "$KC" config use-context x', "H06")
        self.deny("kubectl config view --raw", "H08", "kubectl", "config")
        self.deny("kubectl config view --flatten", "H08")

    def test_kube_run_must_be_the_installed_one(self):
        for cmd in ("kube-run txe-onprem-ci -- get pods", "./kube-run txe-onprem-ci -- get pods",
                    f"{F.root}/other/kube-run txe-onprem-ci -- get pods",
                    "~/bin/kube-run txe-onprem-ci -- get pods"):
            self.deny(cmd, "H09", "kube-run")

    def test_kube_run_arguments(self):
        for rest in H10_RESTS:
            self.deny(kr(rest), "H10", "kube-run")
        for extra in H11_EXTRAS:
            self.deny(kr(f"txe-onprem-ci -- get pods {extra}"), "H11", "kube-run", "get")

    def test_shell_stdin_is_always_checked_as_a_program(self):
        # Connector review of a338d882: with -s, bash runs standard input and its operands are only positional
        # parameters (`bash -s placeholder <<< '...'`). A script operand may run its input too, so stdin fed to a
        # shell is always checked.
        for cmd in ("bash -s placeholder <<< 'kubectl get secrets'", "sh -s a b <<'EOF'\nkubectl get pods\nEOF",
                    "bash -s -- x <<< 'kubectl get ns'", "bash -xs y <<< 'kubectl get ns'", "bash <<< 'kubectl get ns'",
                    "bash ./script.sh <<< 'kubectl get ns'", "bash -c 'cat' <<< 'kubectl get ns'"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)

    def test_watch_shell_option_terminator_and_pipes(self):
        # Connector review of bb40b10c. watch runs its words with `sh -c` unless --exec; a shell's -c string is
        # the first operand after its options (`bash -c -- 'x'`); a shell reading a pipe runs text the hook
        # cannot place.
        for cmd in ("watch 'kubectl get secrets'", "watch -n 5 'kubectl get ns'", "bash -c -- 'kubectl get secrets'",
                    "sh -ec 'kubectl get ns'", "bash -c -x 'kubectl get ns'"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)
        self.deny("watch -x kubectl get ns", "H01", "kubectl")                 # --exec: an argv, not shell text
        for cmd in ("printf '%s\\n' 'kubectl get secrets -A' | bash", "echo kubectl get ns | sh",
                    "echo 'kubectl get ns' | xargs -I{} sh -c '{}'", "printf 'kubectl' | python3 -"):
            self.deny(cmd, "H03")

    def test_a_client_named_where_the_hook_does_not_understand_it_is_refused(self):
        # Class rule (H15): outside the positions the hook classifies (a client's own argv, kube-run, local
        # forms) and outside data-only commands, a client's name is refused rather than guessed about.
        for cmd in ("./deploy.sh kubectl apply -f x", "nohup ./run.sh kubectl get pods",
                    "awk 'BEGIN{system(\"kubectl get ns\")}'", "sed -n 'e kubectl get ns' f"):
            self.deny(cmd, "H15")
        self.deny("tee f <<< x; node x.js kubectl get ns", "H03")              # an interpreter's argument

    def test_data_text_that_reaches_code_is_refused(self):
        # Root: data exemptions are syntax/context-specific. Substitutions, process substitutions, redirections,
        # eval and downstream interpreter pipes can turn apparently textual arguments into code.
        for cmd in ("echo kubectl get ns > >(bash)", "echo kubectl get ns | tee >(sh)", "bash <(echo kubectl get ns)",
                    "source <(echo kubectl get ns)", 'eval "$(echo kubectl get ns)"', "echo kubectl get ns | python3",
                    "cat notes.txt <<< 'kubectl get ns' | bash"):
            self.deny(cmd, "H03")
        for cmd in ("echo $(kubectl get ns)", "echo `kubectl get ns`", "cat <(kubectl get ns)",
                    "grep x <(kubectl get pods)", "echo x > >(kubectl apply -f -)"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)

    def test_documented_false_refusals(self):
        # Expected and documented (README): commands that may send or run text are not data contexts, so text
        # that merely quotes a client name is refused there too.
        for cmd in ("orca orchestration ask --question 'run kubectl get pods?'",
                    "orca orchestration send --text 'kubectl get pods?'", "gh issue comment 1 -b 'kubectl get pods'",
                    "rg kubectl docs", "git -c alias.x='!kubectl get ns' x", "git config alias.k '!kubectl get ns'",
                    "sort --compress-program=kubectl f", "less kubectl.txt kubectl"):
            self.deny(cmd, "H15")

    def test_only_the_small_closed_data_set_with_its_listed_options_is_data(self):
        # Root's review of fc6bc93b: a SMALL closed set of inert forms, not command grammars. man (its pager) and
        # git (configured hooks, pagers, diff drivers, textconv) are not accepted, whatever their flags; unknown,
        # program-carrying, attached and option=value forms refuse when a client is named.
        for cmd in ("man -P 'kubectl get secrets' ls", "man --pager='kubectl get ns' ls", "man -P'kubectl get ns' ls",
                    "man -Pkubectl ls", "man kubectl", "man -k kubectl",
                    "git grep -O'kubectl get ns' x", "git grep -Okubectl x",
                    "git grep --open-files-in-pager='kubectl get ns' x", "git grep --open-files-in-pager=kubectl x",
                    "git log --grep kubectl", "git show HEAD:kubectl.yaml kubectl", "git diff kubectl",
                    "git commit -m 'kubectl notes'", "echo -x kubectl", "grep --pre=x kubectl f", "cat -n kubectl",
                    "grep -A 3 kubectl f", "printf -v x kubectl", "which -s kubectl"):
            self.deny(cmd, "H15")
        # Inherited pagers: a prefix assignment that names a client is refused (H04) before the command.
        for cmd in ("MANPAGER='kubectl get ns' man ls", "PAGER=kubectl man ls", "GIT_PAGER='kubectl get ns' git log"):
            self.deny(cmd, "H04")
        for cmd in ("grep -rn kubectl ops", "grep -c -e kubectl f", "grep -rnE 'kube(ctl|-run)' docs",
                    "echo -n kubectl", "printf 'kubectl %s' x", "cat <<'EOF'\nkubectl get pods\nEOF",
                    "which -a kubectl", "test -n kubectl", "[ -x kubectl ]", ": kubectl"):
            self.assertIsNone(F.run(cmd)[0], cmd)

    def test_a_command_the_hook_cannot_parse_is_refused(self):
        # Connector review of a338d882: `kube\ctl get secrets <<\EOF ...` hid the client from a raw-text match.
        # Any parse failure is now refused (H05); quoted and escaped here-document delimiters parse as bash
        # reads them, and `kube\ctl` is matched without its backslash.
        self.deny("kube\\ctl get secrets <<\\EOF\nx\nEOF", "H01", "kubectl")
        for cmd in ("echo 'unterminated", 'printf "%s', "cat <<EOF\nno end"):
            self.deny(cmd, "H05")

    def test_unreadable_input(self):
        self.deny("kubectl get pods 'unterminated", "H05")
        decision, reason = F.run(None, raw='{"tool_name": "Bash", "tool_input": {"command": "kubectl get')
        self.assertEqual(decision, "deny")
        self.assertIn("rule=H13 ", reason)
        self.assertIn("refused the hook input", reason)


class ValueFreeDiagnostics(unittest.TestCase):
    """Root: diagnostics must not echo command strings, even redacted. A unique sentinel is planted in
    every position a value can take, and must never appear in a refusal."""
    S = "Zq9SENTINELvalue"

    def test_no_value_appears(self):
        S = self.S
        cases = [
            f"kubectl get pods -l app={S}", f"kubectl --context {S} get pods", f"kubectl --kubeconfig /{S} get ns",
            f"kubectl {S}", f"kubectl get {S} -n {S}", f"K={S}kubectl; $K get", f"{S}=kubectl",
            f"bash -c 'kubectl get {S}'", f"python3 -c \"kubectl {S}\"", f"sh <<'EOF'\nkubectl get {S}\nEOF",
            f"X=$(kubectl get {S})", f"helm install {S} ./c", f"flux reconcile ks {S}", f"kubectx {S}",
            f"kubectl config view --raw --minify={S}", f"{F.kr} {S} -- get pods", f"{F.kr} ci -- get pods --token={S}",
            f"/tmp/{S}/kube-run ci -- get pods", f"$({S}) get pods", f"kubectl get pods '{S}", f"{S}|kubectl get pods",
            f"timeout {S} kubectl get pods", f"env {S}=1 kubectl get pods", f"ssh {S} kubectl get pods",
        ]
        for cmd in cases:
            decision, reason = F.run(cmd)
            self.assertEqual(decision, "deny", cmd)
            self.assertNotIn(S, reason, cmd)
            self.assertNotIn(S.lower(), reason.lower(), cmd)

    def test_location_is_an_index_and_a_span(self):
        cmd = "echo a; kubectl get pods; echo b"
        _, reason = F.run(cmd)
        m = re.search(r"command (\d+) of (\d+) \(chars (\d+)-(\d+)", reason)
        self.assertIsNotNone(m, reason)
        k, n, a, b = map(int, m.groups())
        self.assertEqual((k, n), (2, 3))
        self.assertEqual(cmd[a:b], "kubectl get pods")

    def test_subcommand_outside_the_fixed_list_is_other(self):
        _, reason = F.run("kubectl frobnicate pods")
        self.assertIn("subcommand=<other> ", reason)


class Allowed(unittest.TestCase):
    def allow(self, cmd, **kw):
        decision, reason = F.run(cmd, **kw)
        self.assertIsNone(decision, f"{cmd!r} -> {reason}")

    def test_the_installed_kube_run(self):
        for cmd in tuple(kr(rest) for rest in ALLOWED_RESTS) + (
                f"timeout 60 {kr()}", f"bash -c '{kr()}'", f"kubectl config current-context; {kr()}",
                kr('txe-onprem-ci -- get pods -n "$NS"')):
            self.allow(cmd)

    def test_local_commands(self):
        for cmd in ("kubectl version --client", "kubectl version --client=true -o json", "kubectl help", "kubectl",
                    "kubectl --help", "kubectl get pods --help", "kubectl config get-contexts",
                    "kubectl config current-context", "kubectl config view", "kubectl config view --minify",
                    "kubectl kustomize ./overlay", "kubectl completion zsh", "kubectl plugin list",
                    f"kubectl --kubeconfig {F.root}/scratch.yaml config set-context x --cluster y",
                    "kustomize build kubernetes/x", "kustomize build --enable-helm kubernetes/x", "helm version",
                    "helm template x ./chart", "helm lint ./chart", "helm repo list", "flux version --client",
                    "flux install --export", "flux build artifact --path ./k", "oc version --client"):
            self.allow(cmd)

    def test_run_time_command_words_without_cluster_signs(self):
        for cmd in ('"$PY" -m pip list', '"$PY" -c "print(1)"', "$EDITOR notes.md", '"$GO" test ./...'):
            self.allow(cmd)

    def test_here_documents_with_quoted_delimiters_and_script_stdin(self):
        for cmd in ("cat <<\\EOF\nhello\nEOF", 'cat <<"EOF"\nhello\nEOF', "cat <<-'EOF'\n\thello\n\tEOF",
                    "bash ./script.sh <<< 'plain data'"):
            self.allow(cmd)

    def test_data_only_commands_and_pipes_without_a_client(self):
        for cmd in ("echo kubectl get pods | tee notes.txt", "printf x | python3 -", "cat f | bash", "watch -n 5 date",
                    "jq '.items' pods.json", "sort f | uniq -c", "cat <(echo hello)", "echo kubectl > notes.txt",
                    "grep -c kubectl README.md", "source ./env.sh", "git log --oneline", "man ls"):
            self.allow(cmd)

    def test_help_and_client_side_template(self):
        for cmd in ("kubectl get pods --help=false --help", "kubectl get pods -h", "helm template x ./c --dry-run",
                    "helm template x ./c --dry-run=client", "helm template x ./c --dry-run=none"):
            self.allow(cmd)

    def test_unknown_wrapper_options_without_a_client(self):
        for cmd in ("sudo --frobnicate ls", "env --frob true", f"timeout --preserve-status 60 {kr()}"):
            self.allow(cmd)

    def test_text_that_only_mentions_a_client(self):
        for cmd in ("command -v kubectl", "which kubectl helm flux", "grep -rn kubectl ops", "echo kubectl get pods",
                    "cat ops/flux/prod.sh", "python3 ops/flux/classify-diff.py x", "bash ops/flux/staging.sh --help",
                    "cat > notes.md <<'EOF'\nkubectl get pods\nEOF"):
            self.allow(cmd)

    def test_input_with_no_command_is_ignored(self):
        self.assertEqual(F.run(None, raw="not json"), (None, ""))
        self.assertEqual(F.run(None, raw='{"tool_name": "Bash", "tool_input": {}}'), (None, ""))
        self.allow(None, tool="Read", tool_input={"file_path": "/x/kubectl-notes.md"})


class EventShapes(unittest.TestCase):
    """Only the Claude Code Bash shape is guarded. Every other shape is hand-written here (none is a captured
    payload): an unsupported shape with a command-like field that names a client fails closed (H14) and is
    never parsed. A clean command in an unsupported shape is allowed, which means NOT GUARDED, not protected."""

    def decide(self, tool, tool_input):
        return F.run(None, tool=tool, tool_input=tool_input)

    def test_the_guarded_shape_is_parsed(self):
        decision, reason = self.decide("Bash", {"command": "echo a; kubectl get pods"})
        self.assertEqual(decision, "deny")
        self.assertIn("rule=H01 ", reason)                 # parsed: a rule from the lexer, with a location
        self.assertIn("command 2 of 2", reason)

    def test_unsupported_shapes_that_name_a_client_fail_closed_and_are_not_parsed(self):
        for tool, tool_input in (
                ("shell", {"command": ["bash", "-lc", "kubectl get pods"]}),     # argv list
                ("shell", {"command": "kubectl get pods"}),
                ("exec_command", {"cmd": "kubectl get pods -A"}),
                ("exec_command", {"cmd": ["kubectl", "get", "ns"]}),
                ("Bash", {"command": ["kubectl", "get", "pods"]}),              # Bash, but not a string
                ("Bash", {"cmd": "kubectl get pods"}),
                ("Monitor", {"command": "kubectl get pods -w"}),
                ("Read", {"command": "kubectl get pods"})):
            decision, reason = self.decide(tool, tool_input)
            self.assertEqual(decision, "deny", (tool, tool_input))
            self.assertIn("rule=H14 ", reason)
            self.assertIn("refused the hook input", reason)  # no location: the text was not parsed

    def test_unsupported_shapes_without_a_client_are_allowed_unguarded(self):
        for tool, tool_input in (("shell", {"command": ["ls", "-la"]}), ("exec_command", {"cmd": "git status"}),
                                 ("Edit", {"file_path": "/x/a.py", "old_string": "a", "new_string": "b"}),
                                 # kube-run is not a client name, so this shape passes UNGUARDED: the hook
                                 # checks none of H09-H11 on it. kube-run still runs every check of its own.
                                 ("shell", {"command": f"{F.kr} txe-onprem-ci -- get pods"})):
            self.assertEqual(self.decide(tool, tool_input), (None, ""), (tool, tool_input))


class PairingWithKubeRun(unittest.TestCase):
    """S1b: the hook against the FINAL kube-run CLI in this tree."""

    def test_the_override_lists_are_the_same_list(self):
        self.assertEqual(set(GUARD.KUBE_RUN_OVERRIDES), set(KR.OVERRIDE_FLAGS))

    def test_every_form_the_hook_lets_through_parses_in_kube_run(self):
        for rest in ALLOWED_RESTS:
            self.assertIsNone(F.run(kr(rest))[0], rest)
            record, timeout, cluster_id, kargs = KR.parse_cli(shlex.split(rest))
            self.assertTrue(KR.CLUSTER_ID.match(cluster_id), rest)
            self.assertFalse(any(KR.is_override(a) for a in kargs), rest)
            self.assertTrue(kargs, rest)

    def test_an_argument_form_the_hook_refuses_is_refused_by_kube_run_too(self):
        for rest in H10_RESTS:
            if "$" in rest:
                continue                    # a shell variable: only the hook sees the unexpanded text
            try:
                _, _, cluster_id, _ = KR.parse_cli(shlex.split(rest))
            except KR.Refused as r:
                self.assertEqual(r.code, "KR01", rest)
                continue
            # parse_cli takes any word as the id; load_entry then refuses an id that is not well formed (KR03).
            self.assertFalse(KR.CLUSTER_ID.match(cluster_id), rest)

    def test_an_override_the_hook_refuses_is_an_override_to_kube_run(self):
        for extra in H11_EXTRAS:
            _, _, _, kargs = KR.parse_cli(shlex.split(f"txe-onprem-ci -- get pods {extra}"))
            self.assertTrue(any(KR.is_override(a) for a in kargs), extra)
            with self.assertRaises(KR.Refused) as cm:
                KR.parse_request(kargs, "default")
            self.assertEqual(cm.exception.code, "KR04", extra)


class ShortOptionPairing(unittest.TestCase):
    """The hook and kube-run each keep a copy of the shorthand rule, because the hook must run standalone. This
    pins the copies to each other for every value-taking letter and every recognised boolean letter, in every
    form pflag reads: bare, attached (-xVALUE), with = (-x=V), clustered before and after s, and after `--`.
    The hook's side runs in-process (its Guard class), so that hundreds of forms stay fast; Refused and
    PairingWithKubeRun cover the subprocess path."""

    BOOLEAN_LETTERS = "AitwRhq"

    def forms(self):
        for x in sorted(KR.SHORT_VALUE_LETTERS) + list(self.BOOLEAN_LETTERS):
            yield from (f"-{x}", f"-{x}VALUE", f"-{x}=V", f"-{x}https://h", f"-i{x}s", f"-{x}s", f"-s{x}",
                        f"-it{x}")

    def hook_refuses_h11(self, kargs):
        cmd = f"{F.kr} txe-onprem-ci -- {kargs}"
        try:
            GUARD.Guard(os.path.realpath(F.kr), None, cmd).check_top(cmd)
        except GUARD.Refusal as r:
            self.assertEqual(r.rule, "H11", cmd)   # an allowed kube-run form can only fail as an override
            return True
        return False

    def kube_run_refuses_kr04(self, args):
        try:
            KR.parse_request(args, "default")
        except KR.Refused as r:
            return r.code == "KR04"
        return False

    def test_the_value_letter_sets_are_the_same_set(self):
        self.assertEqual(GUARD.SHORT_VALUE_LETTERS, KR.SHORT_VALUE_LETTERS)
        # The hook's third copy: the short options first_operand skips together with their value.
        self.assertEqual({o[1] for o in GUARD.SHORT_VALUED}, KR.SHORT_VALUE_LETTERS)
        self.assertTrue(all(len(o) == 2 and o[0] == "-" for o in GUARD.SHORT_VALUED))
        self.assertFalse(set(self.BOOLEAN_LETTERS) & KR.SHORT_VALUE_LETTERS)

    def test_every_short_form_gets_the_same_verdict_from_both(self):
        seen = {True: 0, False: 0}
        for a in self.forms():
            override = KR.is_override(a)
            seen[override] += 1
            self.assertEqual(GUARD.short_cluster_has(a, "s"), KR.short_cluster_has(a, "s"), a)
            self.assertEqual(self.hook_refuses_h11(f"get pods {a}"), override, a)
            self.assertEqual(self.kube_run_refuses_kr04(["get", "pods", a]), override, a)
            # After the terminator, both still read the token (kube-run scans every argument for overrides).
            self.assertEqual(self.hook_refuses_h11(f"get pods -- {a}"), override, a)
            self.assertEqual(self.kube_run_refuses_kr04(["get", "pods", "--", a]), override, a)
        self.assertTrue(seen[True] and seen[False], seen)   # both verdicts were exercised

    def test_the_value_letters_end_the_cluster(self):
        for x in sorted(KR.SHORT_VALUE_LETTERS - {"s"}):
            self.assertFalse(KR.is_override(f"-{x}s"), x)          # the s is the value of -x
            self.assertTrue(KR.is_override(f"-s{x}"), x)           # -s first takes x as its value
        for x in self.BOOLEAN_LETTERS:
            self.assertTrue(KR.is_override(f"-{x}s"), x)           # a boolean, then -s


if __name__ == "__main__":
    unittest.main()
