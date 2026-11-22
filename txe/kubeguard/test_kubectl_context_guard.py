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
                 "--timeout 30 txe-onprem-ci -- logs pod/x -c y",
                 "--timeout 30 --authorization /x/rec.json txe-onprem-ci -- get pod x",
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

    def test_quote_decoded_names_mark_the_line_for_pipe_receivers(self):
        # Connector review of 77f1bac3: `echo kube''ctl get secrets | bash` was allowed. Bash's quote removal
        # makes echo print `kubectl get secrets`, which the downstream shell runs; the line-level check read only
        # the raw text, so the receiver skipped H03. Every quote-removal spelling now marks the line.
        for name in ("kube''ctl", 'kube""ctl', "'kube'ctl", 'kube"c"tl', "k\\ubectl", "kube$''ctl", 'kube$""ctl',
                     "$'kubectl'", "$'\\x6bubectl'", "kube$'\\x63'tl", "$'\\153ubectl'", "$'\\u006bubectl'",
                     "kube\\\nctl", "he''lm", "fl''ux"):
            for cmd in (f"echo {name} get secrets | bash", f"printf '%s\\n' {name} | sh",
                        f"echo {name} get ns > >(bash)", f"bash <(echo {name} get ns)",
                        f"echo {name} get ns | python3"):
                self.deny(cmd, "H03")
        # A here-document body is decoded as text, without parsing it.
        for body in ("kube''ctl get secrets", 'kube"c"tl get ns', "$'\\x6bubectl' get ns"):
            self.deny(f"cat <<'EOF' | bash\n{body}\nEOF", "H03")
            self.deny(f"ssh host <<'EOF'\n{body}\nEOF", "H03")
        # The direct spellings stay H01 (Allowed.test_quote_decoded_data_without_a_code_receiver has the data side).
        self.deny("kube''ctl get pods", "H01")

    def test_brace_alternatives_mark_the_line_for_pipe_receivers(self):
        # Root msg_205b648bd468: deterministic brace alternatives are expanded structurally (not by deleting braces,
        # which would read `kube{ctl,x}` as `kubectlx`), bounded, and fail closed past the bound.
        for name in ("kube{ctl,x}", "kube{ctl,}", "{kubectl,x}", "{x,kubectl}", "{ku,x}be{ctl,y}",    # suffix, prefix
                     "ku{b{e,x},y}ctl", "k{u,x}{b,y}{e,z}ctl",                                        # nested, adjacent
                     "kub{e..e}ctl", "k{8..9}s", "k{1..500}s", "k{9..1..2}s", "kube{c..d}tl",          # sequences
                     "kube{\"ctl\",x}", "kube{'c'tl,x}", "{he,x}lm", "{fl,x}ux", "kube{ctl,x}{,}"):
            for cmd in (f"echo {name} get secrets | bash", f"printf '%s\\n' {name} | sh",
                        f"echo {name} get ns > >(bash)", f"bash <(echo {name} get ns)",
                        f"echo {name} get ns | python3"):
                self.deny(cmd, "H03")
        # Braces inside a quoted string that a nested shell reads, and braces quoted or escaped for THIS shell that
        # the downstream shell then expands (`echo kube\{ctl,x\}` prints `kube{ctl,x}`, which `bash` expands).
        r = self.deny("bash -c 'echo kube{ctl,x} get secrets | bash'", "H03")
        self.assertIn("nested", r)
        for cmd in ("echo kube\\{ctl,x\\} get secrets | bash", "echo 'kube{ctl,x}' get secrets | bash",
                    'echo "{kube,x}ctl get secrets" | sh'):
            self.deny(cmd, "H03")
        self.deny("cat <<'EOF' | bash\necho kube{ctl,x} get secrets\nEOF", "H03")
        # Over a bound: refused as if it named a client (the line reaches a shell).
        self.deny("echo " + "{a,b}" * 9 + " | bash", "H03")                         # 512 > 256 words
        self.deny("echo " + "{a," * 17 + "b" + "}" * 17 + " | bash", "H03")          # nesting 17 > 16
        self.deny("echo {a..z}{a..z} | sh", "H03")                                   # 676 > 256 words
        self.deny("echo {0.." + "9" * 5000 + "} | sh", "H03")                       # an endpoint int() refuses
        # As a command word, the word itself is not a client name, so it is an unclassified command naming one.
        self.deny("kube{ctl,x} get pods", "H15")

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

    def test_attached_wrapper_option_payloads_are_inspected(self):
        # Connector security review of 77689338: `env -S'kubectl get secrets -A'` was allowed, because the
        # attached -S payload was dropped and the unknown-option path checked only the words AFTER the option.
        # Closed wrapper grammar: an attached payload is inspected before it is skipped, `--name=value` is accepted
        # only for a listed option (its value inspected), and any unknown option is refused in a client line.
        for cmd in ("env -S'kubectl get secrets -A'", 'env -S"kubectl get ns"', "env -S'bash -c \"kubectl get ns\"'"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)
        for cmd in ("sudo -ukubectl ls", "timeout -skubectl 5 ls", "xargs -Ikubectl echo x", "nice -nkubectl ls",
                    "sudo --prompt=kubectl ls", "timeout --signal=kubectl 5 ls", "sudo --frob=x kubectl get pods",
                    "timeout -sKILL 5 kubectl get pods", "kubectl version --client; nice -z ls",
                    "sudo --user= kubectl get pods"):
            self.deny(cmd, "H03")
        # Benign attached and equals forms with no client stay allowed.
        for cmd in ("sudo -uroot ls", "timeout -sKILL 5 date", "env -Sdate", "xargs -I{} echo {}",
                    "sudo --prompt=pw ls", "nice -n5 ls"):
            self.assertIsNone(F.run(cmd)[0], cmd)

    def test_local_forms_accept_only_their_listed_options(self):
        # Connector review of 24ac0dca: `helm template ... --post-renderer kubectl` was "local", and Helm execs the
        # post-renderer. Root's contract: a local verdict stands only for a closed, evidenced per-form grammar
        # (LOCAL_FORMS); every option occurrence is checked; executable, plugin, function and post-renderer
        # controls are in no form, whatever they name. All inert strings; nothing is executed.
        # The exact repro names kubectl, so DEFENCE IN DEPTH refuses it first (H03). Without a client name, the
        # grammar itself refuses (H07).
        self.deny("helm template demo ./chart --post-renderer kubectl --post-renderer-args=get "
                  "--post-renderer-args=secrets", "H03")
        for cmd in ("kubectl config get-contexts kubectl", "helm template kubectl ./c"):
            self.deny(cmd, "H03")
        for cmd in (
                # helm template: execution, download and unlisted options, in every position and form.
                "helm template x ./chart --post-renderer ./render.sh", "helm template x ./chart --post-renderer=./x",
                "helm template x ./chart --post-renderer-args=a", "helm template x ./chart --dependency-update",
                "helm template x ./chart --repo https://charts.example", "helm template x ./c -f https://x/v.yaml",
                "helm template x repo/chart", "helm template x ./c --dry-run=none", "helm template x ./c --dry-run client",
                "helm template x ./c --frob", "helm --debug template x ./c", "helm template x ./c -z",
                "helm template x ./c -gz", "helm template x ./c -f", "helm template x ./c --set=",
                # helm: plugin, dependency and repo-mutating forms are not local; help only for a built-in.
                "helm plugin install https://example.com/p", "helm plugin list", "helm dependency build ./c",
                "helm repo add x https://charts.example", "helm unknownplugin --help",
                # flux: only version --client, completion, build artifact and install --export, with listed options.
                "flux build artifact --path ./k --frob", "flux install --export -v 2.3.0",
                "flux install --export --registry-creds u:p", "flux create source git x --url y --export",
                "flux envsubst", "flux build kustomization x --path ./k --dry-run",
                "flux push artifact oci://example/x --path ./k",
                # Pinned-source review (flux v2.9.4): --add-ignore-paths does not exist; a non-built-in is a plugin.
                "flux build artifact --path ./k --add-ignore-paths x", "flux trigger --help", "flux get --help"):
            self.deny(cmd, "H07")
        # Pinned-source review (kubectl v1.34.9 cmd.go:144-175): `create <unknown> --help` runs a kubectl-create-*
        # plugin, and kuberc is no v1.34.9 command.
        for cmd in ("kubectl create foo --help", "kubectl create --help", "kubectl kuberc --help"):
            self.deny(cmd, "H01")
        for cmd in (
                # kubectl kustomize is no local form (helm, plugins, functions, git URLs).
                "kubectl kustomize ./o", "kubectl kustomize ./o --enable-helm", "kubectl kustomize ./o --enable-alpha-plugins",
                "kubectl kustomize ./o --helm-command x",
                # kubectl: unlisted options, invalid or missing values, and help for a non-built-in (a plugin).
                "kubectl version --client --frob", "kubectl version --client -o wide", "kubectl version --client -o",
                "kubectl --frob version --client", "kubectl completion tcsh", "kubectl config view -o jsonpath={x}",
                "kubectl foo --help", "oc version --client"):
            self.deny(cmd, "H01")
        for cmd in (
                # standalone kustomize: only `kustomize build <local dir>`, with no options.
                "kustomize build --enable-helm kubernetes/x", "kustomize build ./o --enable-alpha-plugins",
                "kustomize build --enable-exec ./o", "kustomize build --helm-command x ./o",
                "kustomize build github.com/x/y", "kustomize build https://github.com/x/y", "kustomize version",
                "kustomize build"):
            self.deny(cmd, "H03")

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
                    "bash -s -- x <<< 'kubectl get ns'", "bash -xs y <<< 'kubectl get ns'", "bash <<< 'kubectl get ns'"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)
        # Root's channel contract (e8f4de9f review): a script operand is an opaque channel, and -c plus a
        # here-string is two channels. Both are refused, not inspected.
        for cmd in ("bash ./script.sh <<< 'kubectl get ns'", "bash -c 'cat' <<< 'kubectl get ns'"):
            self.deny(cmd, "H03")

    def test_every_input_of_a_code_running_command_is_one_inline_program_or_refused(self):
        # Connector review of e8f4de9f, and root's narrower contract: in a line that names a client, a shell,
        # source/., eval or interpreter is inspected only through EXACTLY ONE literal inline program channel.
        # Everything else is refused (H03). All inert strings; nothing is executed.
        # The literal inline channels, inspected recursively (H01 nested):
        for cmd in ("bash -c 'kubectl get secrets'", "bash --norc -c 'kubectl get ns'",
                    "bash --noprofile --login -c 'kubectl get ns'", "bash -o pipefail -c 'kubectl get ns'",
                    "bash +O extglob -c 'kubectl get ns'", "sh <<'EOF'\nkubectl get pods\nEOF",
                    "bash <<< 'kubectl get ns'", "eval kubectl get ns", "eval 'kubectl get ns'"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)
        for cmd in (
                # P1 4655152382: source/. of any file is opaque, even /dev/stdin with inspected input.
                "source /dev/stdin <<< 'kubectl get secrets'", ". /dev/stdin <<< 'kubectl get ns'",
                "source /dev/stdin <<'EOF'\nkubectl get pods\nEOF", "source ./x.sh; kubectl version --client",
                # P1 4655152390: startup-file options are opaque, even with a later visible -c; unknown and
                # attached long options fail closed.
                "bash --rcfile /dev/null -c 'kubectl get secrets'", "bash --init-file /dev/null -c 'kubectl get ns'",
                "bash --rcfile=/dev/null -c 'kubectl get ns'", "bash --norc=1 -c 'kubectl get ns'",
                "bash --frob -c 'kubectl get ns'", "bash -Z -c 'kubectl get ns'", "bash -o kubectl -c 'x'",
                "bash -oc pipefail 'kubectl get ns'",
                # Root's review of f7b4da60: an empty word reached a[0] (IndexError). Empty words, missing, empty
                # or non-literal option values, and non-literal option words are refused, never indexed or inferred.
                "bash '' -c 'kubectl get ns'", 'bash "" -c \'kubectl get ns\'', "bash -c '' 'kubectl get ns'",
                "bash -o '' -c 'kubectl get ns'", "bash -o; kubectl version --client",
                "bash -o \"$V\" -c 'kubectl get ns'", "bash -$X -c 'kubectl get ns'", 'bash "$OPT" -c \'kubectl get ns\'',
                # P2 4655180803: input redirections, process substitutions included, are opaque.
                "bash < <(printf 'kubectl get secrets -A\\n')", "bash < script.sh; kubectl version --client",
                "sh <&3; kubectl version --client", "eval 'kubectl get ns' < f",
                # More than one channel, none, or a non-literal one.
                "bash -c 'kubectl get ns' <<'EOF'\nx\nEOF", "eval true <<< x; kubectl version --client",
                "bash <<EOF\nkubectl get pods\nEOF", 'bash -c "$CMD"; kubectl version --client',
                "bash -c; kubectl version --client", "bash; kubectl version --client", "eval; kubectl version --client",
                'eval "$X"; kubectl version --client', "bash x.sh; kubectl version --client",
                # Interpreters: no program channel of theirs is modelled.
                "python3 x.py; kubectl version --client", "python3 - <<'EOF'\nprint(1)\nEOF\nkubectl version --client",
                "node -e 1; kubectl version --client"):
            self.deny(cmd, "H03")
        # No-client positives: the classifier applies only to client-relevant lines. This makes no wider claim
        # about hidden code (see the README's limits).
        for cmd in ("source ./env.sh", "bash --rcfile /dev/null -c 'echo hi'", "bash < <(echo date)",
                    "python3 x.py", "bash ./script.sh <<< 'plain data'"):
            self.assertIsNone(F.run(cmd)[0], cmd)

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

    def test_wrapper_options_with_an_optional_value_and_consumed_values(self):
        # Connector review of 7441b7b6: `watch -d` was read as taking the next word, so the whole command was
        # dropped before watch's sh -c check. GNU getopt `x::` options (watch -d/--differences, xargs -i/--replace,
        # -e/--eof, -l) take an OPTIONAL value that can only be attached: the bare form consumes nothing.
        for cmd in ("watch -d 'kubectl get secrets'", "watch --differences 'kubectl get ns'",
                    "watch --differences=1 'kubectl get ns'", "watch -d -n 5 'kubectl get ns'"):
            r = self.deny(cmd, "H01", "kubectl")
            self.assertIn("nested", r, cmd)
        for cmd in ("echo ns | xargs -i kubectl get", "echo ns | xargs --replace kubectl get {}",
                    "xargs -l kubectl get < f", "xargs --max-lines kubectl get < f", "xargs -e kubectl get < f"):
            self.deny(cmd, "H01", "kubectl")
        # An attached optional value is not modelled: unknown, so it fails closed when a client follows.
        for cmd in ("watch -d1 kubectl get ns", "xargs -ifoo kubectl get foo"):
            self.deny(cmd, "H03")
        # A word consumed as a REQUIRED value never names a client: refused, not skipped (a wrong arity entry
        # then fails closed).
        for cmd in ("watch -n kubectl ls", "timeout -s kubectl 5 ls", "xargs -I kubectl echo x", "sudo -u kubectl ls"):
            self.deny(cmd, "H03")

    def test_kube_run_runs_bare_with_no_environment_change(self):
        # Connector security review of 7441b7b6: `PATH=/tmp/bin <kube-run>` let the environment choose the
        # interpreter of kube-run's `env python3` shebang. Root's contract (after two closed-set rounds): the kube-run
        # exception holds only when the WHOLE command is ONE bare kube-run invocation with literal arguments. Every
        # case below, from all three review rounds, is another shape, so all are H16.
        for cmd in (f"PATH=/tmp/bin {kr()}", f"PYTHONPATH=/tmp/x {kr()}", f"env PATH=/tmp/bin {kr()}",
                    f"env -i {kr()}", f"timeout 60 {kr()}", f"timeout --preserve-status 60 {kr()}", f"sudo {kr()}",
                    f"nohup {kr()}", f"command {kr()}", f"time {kr()}", f"PATH=/tmp/bin; {kr()}",
                    f"export PATH=/tmp/bin; {kr()}", f"{kr()}; export X=1", f"source ./env.sh && {kr()}",
                    f"PATH=/tmp/bin bash -c '{kr()}'", f"bash -c 'X=1; {kr()}'", f"declare -x PATH=/tmp/bin; {kr()}",
                    f"set -a; X=1; {kr()}", f"hash -p /tmp/py python3; {kr()}", f"unset PATH; {kr()}"):
            self.deny(cmd, "H16", "kube-run")
        # cc3's review of 1f761b1d: H16 is an ALLOWLIST. Every other command must be environment-neutral, so the
        # builtins a denylist would miss, other assignment forms and unknown commands are all refused.
        for cmd in (f"PATH+=:/tmp/bin; {kr()}", f"PYTHONPATH+=/x {kr()}", f"arr[0]=x; {kr()}",
                    f"read -r PATH <<< /tmp/bin; {kr()}", f"printf -v PATH %s /tmp/bin; {kr()}",
                    f"mapfile -t PATH < f; {kr()}", f"let X=1; {kr()}", f"getopts ab PATH; {kr()}", f"foo; {kr()}",
                    f"python3 x.py; {kr()}", f"eval true; {kr()}", f"bash -c 'read PATH'; {kr()}"):
            self.deny(cmd, "H16", "kube-run")
        # cc3's review of ec45aaa5 and root's narrowing: `set` is neutral only with a closed option list;
        # assignment expansions and unsupported syntax are refused; no external command, wrapper or non-kubectl
        # local form is neutral; neither is a shell given a script, nor an output redirection to a file.
        for cmd in (f"set -k; {kr('txe-onprem-ci -- get pods PATH=/tmp/bin')}", f"set -o keyword; {kr()}",
                    f"set -a; {kr()}", kr("txe-onprem-ci -- get pods PATH=/tmp/bin"),
                    f"echo ${{PYTHONPATH:=/tmp/x}}; {kr()}", f"echo ${{X=1}}; {kr()}", f"echo $((PATH=5)); {kr()}",
                    f"((X=1)); {kr()}", f'echo "${{NS}}"; {kr()}', f"[[ -n x ]] && {kr()}", f"f() {{ true; }}; {kr()}",
                    f"for i in 1; do true; done; {kr()}", f"date; {kr()}", f"kustomize build x; {kr()}",
                    f"helm version; {kr()}", f"timeout 5 true; {kr()}", f"command -v kubectl; {kr()}",
                    f"bash x.sh; {kr()}", f"echo x > /tmp/f; {kr()}", f"{kr()} > out.txt"):
            self.deny(cmd, "H16", "kube-run")
        # Root's single-invocation grammar: arithmetic ++/-- and indirect expansion, the shapes the closed set
        # allowed (now EXPECTED FALSE REFUSALS, documented in the README), and every non-literal argument.
        for cmd in (f"(( X++ )); {kr()}", f"echo $((X--)); {kr()}", f"echo ${{!x}}; {kr()}",
                    f"bash -c '{kr()}'", f"kubectl config current-context; {kr()}", f"cd /tmp && {kr()}",
                    f"if {kr()}; then echo ok; fi", f"{kr()} | grep Running", f"set -euo pipefail; {kr()}",
                    f"set -e; {kr()}", f"{kr()} 2>&1", f"{kr()} 2>/dev/null", f"{kr()} < /dev/null", f"{kr()} &",
                    f"{kr()};", f"{kr()} # note", f"{kr()}\n", f"{kr()} <<< x", f"echo $({kr()})",
                    kr('txe-onprem-ci -- get pods -n "$NS"'), kr("txe-onprem-ci -- get pods -n ${NS}"),
                    kr("txe-onprem-ci -- get pods -n $(echo x)"), kr("txe-onprem-ci -- get pods -n `echo x`"),
                    kr("txe-onprem-ci -- get pods -n $((1))"), kr("txe-onprem-ci -- get pods -o jsonpath={.items}"),
                    kr("txe-onprem-ci -- get pods/*"), kr("txe-onprem-ci -- get pods a\\ b"),
                    kr("txe-onprem-ci -- get pods $'x'"), kr("txe-onprem-ci -- get pods !x")):
            self.deny(cmd, "H16", "kube-run")
        # literal_word: quote removal alone, with no evaluation.
        for raw in ("abc", "'a b'", '"x y"', "a'b'c", "app=web", "'jsonpath={.items}'", '"app in (a)"',
                    "/x/rec.json", "deploy/x", "-n", "--since=1h", "'$X'"):
            self.assertTrue(GUARD.literal_word(raw), raw)
        for raw in ("~/x", "$X", '"$X"', "a*", "{a,b}", "\\x", "$'x'", '"a\\b"', "!x", "#x", "'open", '"open',
                    "x[0]", "`x`", '"`x`"', ""):
            self.assertFalse(GUARD.literal_word(raw), raw)
        # The widened assignment forms get the H04 check on their value too.
        for cmd in ("X+=kubectl", "a[1]=kubectl", "K[0]+=kubectl true"):
            self.deny(cmd, "H04")

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

    def test_the_bracket_test_command_is_classified_before_the_glob_check(self):
        # run-s1-local-09 found `[ -x kubectl ]` refused as a run-time command word: `[` contains a glob character.
        # Root's ruling: the EXACT word `[` with a closing `]` is the POSIX test command, classified before DYNAMIC
        # with test's rules. Genuinely dynamic bracket words stay H02; malformed syntax is H05; substitutions inside
        # are still classified recursively; and pipeline rules still apply.
        for cmd in ("[a-z] kubectl get ns", "[k]ubectl get pods", "x[ kubectl ]"):
            self.deny(cmd, "H02")
        for cmd in ("[ -x kubectl", "[ -x kubectl ] ]x", "["):
            self.deny(cmd, "H05")
        r = self.deny('[ "$(kubectl get ns)" ]', "H01", "kubectl")
        self.assertIn("nested", r)
        self.deny("[ -x kubectl ] | bash", "H03")
        for cmd in ("[ -x kubectl ]", "[ -n kubectl ] && echo y", '[ "$X" = kubectl ]', "[ -f ./kubectl ]"):
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
        # H16's grammar: ONE bare kube-run invocation with literal arguments, quoting decoded without evaluation.
        # Every other shape is refused; see Refused.test_kube_run_runs_bare_with_no_environment_change.
        for cmd in tuple(kr(rest) for rest in ALLOWED_RESTS) + (
                kr("txe-onprem-ci -- get pods -l app=web"), kr("txe-onprem-ci -- get pods -l 'app in (a,b)'"),
                kr("txe-onprem-ci -- get pods -o 'jsonpath={.items[*].metadata.name}'"),
                kr('txe-onprem-ci -- get pods -l "tier=web"'), f"  {kr()}  ", kr("txe-onprem-ci --\tget pods")):
            self.allow(cmd)

    def test_local_commands(self):
        for cmd in ("kubectl version --client", "kubectl version --client=true -o json", "kubectl help", "kubectl",
                    "kubectl --help", "kubectl get pods --help", "kubectl config get-contexts",
                    "kubectl config current-context", "kubectl config view", "kubectl config view --minify",
                    "kubectl completion zsh", "kubectl plugin list",
                    f"kubectl --kubeconfig {F.root}/scratch.yaml config set-context x --cluster y",
                    "kustomize build kubernetes/x", "helm version",
                    "helm template x ./chart", "helm lint ./chart", "helm repo list", "flux version --client",
                    "flux install --export", "flux build artifact --path ./k",
                    # Benign supported renders and reads, in the closed per-form grammar (LOCAL_FORMS):
                    "kubectl version --client -ojson", "kubectl version --client --output=yaml",
                    "kubectl --kubeconfig ./k.yaml config view --minify -o json", "kubectl config get-contexts -o name",
                    "kubectl plugin list --name-only", "kubectl help get", "helm help template", "helm version --short",
                    "helm template x ./chart -n ns -f values.yaml --set a=b --include-crds",
                    "helm template ./chart -g --dry-run=client", "helm lint ./chart --strict -f v.yaml",
                    "helm repo list -o json", "helm completion zsh", "helm env", "flux completion zsh",
                    "flux version --client -o json", "flux build artifact -p ./k -o ./a.tgz",
                    "flux install --export --components-extra=image-reflector-controller"):
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
                    "helm template x ./c --dry-run=client"):
            self.allow(cmd)

    def test_unknown_wrapper_options_without_a_client(self):
        for cmd in ("sudo --frobnicate ls", "env --frob true", "timeout --preserve-status 60 date",
                    "watch -d date", "watch --differences=1 date", "watch -d -n 5 date", "echo a | xargs -i echo {}",
                    "echo a | xargs --replace echo {}"):
            self.allow(cmd)

    def test_text_that_only_mentions_a_client(self):
        for cmd in ("command -v kubectl", "which kubectl helm flux", "grep -rn kubectl ops", "echo kubectl get pods",
                    "cat ops/flux/prod.sh", "python3 ops/flux/classify-diff.py x", "bash ops/flux/staging.sh --help",
                    "cat > notes.md <<'EOF'\nkubectl get pods\nEOF"):
            self.allow(cmd)

    def test_quote_decoded_data_without_a_code_receiver(self):
        # The quote-decoded mention check (mention_forms) adds refusals only where a client-relevant line reaches
        # code. A decoded name in plain data is still data, and quoting that assembles no name is not a mention.
        for cmd in ("echo kube''ctl get pods", "echo kube''ctl get pods > notes.txt", "echo 'it''s' | bash",
                    "echo \"don't\" | sh", "echo 'kube' ctl | bash", "printf '%s\\n' kube ctl | sh"):
            self.allow(cmd)

    def test_brace_forms_that_assemble_no_client_name(self):
        # Literal braces (no comma, not a sequence), unmatched braces, quoted or escaped braces, ${...}, braces
        # split across words, and alternatives that form no name stay allowed. Over-budget forms in plain data
        # are allowed too: the bound refuses only where a mention would.
        for cmd in ("echo kube{ctl} | bash", "echo kube{ctl,x | bash", "echo {kube,x} ctl | bash",
                    "echo ${HOME} | bash", "echo {1..3} | sh", "echo {a..z} | sh", "echo {1..5000} | sh",
                    "mkdir -p a/{b,c}", "echo " + "{a,b}" * 9,
                    "find . -name x -exec echo {} \\;"):
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
