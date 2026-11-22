# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for guard-hook.py (TXE-8055). shellguard_test.go runs this file; directly:
    python3 -I -B test_guard_hook.py -v

Every fixture is a STRING handed to a pure function or to main() with in-memory streams. No fixture
is ever evaluated as shell: this file starts no process, opens no file but the guard's own source
(read as text for the structural test), and uses no network. The incident fixtures are sanitized
SHAPES with placeholder command words (step-one, step-two); no real merge, deploy or cluster
command appears anywhere.
"""
import ast
import importlib.util
import io
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "guard-hook.py"
spec = importlib.util.spec_from_file_location("guard_hook", SOURCE)
assert spec is not None and spec.loader is not None
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

BT = "`"  # a backtick, kept out of the literals below so each fixture reads plainly


def rules(text):
    return [r for r, _ in G.check(text)]


def decide_raw(raw):
    """main() on raw hook-input bytes, in-process with in-memory streams. Returns (exit code, stderr)."""
    err = io.StringIO()
    rc = G.main(io.BytesIO(raw), err)
    return rc, err.getvalue()


def decide(payload):
    return decide_raw(json.dumps(payload).encode("utf-8"))


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


class IncidentShapes(unittest.TestCase):
    """Sanitized shapes of the two 2026-11-22 instances. Placeholder words only."""

    def test_instance_a_unquoted_heredoc_building_a_body_is_refused_without_any_send(self):
        cmd = ("S=/scratch; cat >| $S/msg.txt <<EOF\n"
               "Packet text. Then run " + BT + "step-one --fetch" + BT + " and "
               + BT + "step-two -I <(step-three ref:script.py) 471" + BT + ".\n"
               "EOF\n")
        self.assertIn("H1", rules(cmd))

    def test_instance_a_with_its_send_line_is_refused(self):
        cmd = ("cat >| /s/m.txt <<EOF\nrun " + BT + "step-one 471" + BT + "\nEOF\n"
               "test -s /s/m.txt && acmectl send --body \"$(cat /s/m.txt)\"")
        self.assertEqual(sorted(set(rules(cmd))), ["H1", "T2"])

    def test_instance_b_backtick_in_an_inline_double_quoted_body_is_refused(self):
        cmd = ('orca orchestration send --to dispatch:ctx_x --subject "s" --body "Hold: run '
               + BT + "step-one suspend thing-a thing-b -n ns" + BT + ' only on GO."')
        self.assertEqual(rules(cmd), ["D1"])


class Rules(unittest.TestCase):
    def test_d1_backtick_in_double_quotes(self):
        self.assertEqual(rules('echo "a ' + BT + "x" + BT + ' b"'), ["D1"])

    def test_t2_dollar_paren_in_double_quotes_any_length(self):
        self.assertEqual(rules('echo "$(x)"'), ["T2"])
        self.assertEqual(rules('V="$(git rev-parse HEAD)"'), ["T2"])

    def test_t2_reaches_through_parameter_expansion(self):
        self.assertEqual(rules('echo "${V:-$(x)}"'), ["T2"])

    def test_t2_reaches_through_arithmetic_in_double_quotes(self):
        self.assertEqual(rules('echo "$(( $(x) + 1 ))"'), ["T2"])

    def test_zsh_dollar_paren_lt_form_is_a_substitution(self):
        self.assertEqual(rules('acmectl send --body "$(<f)"'), ["T2"])

    def test_h1_both_forms_in_unquoted_heredoc(self):
        self.assertEqual(rules("cat <<EOF\n" + BT + "x" + BT + "\nEOF\n"), ["H1"])
        self.assertEqual(rules("cat <<EOF\n$(x)\nEOF\n"), ["H1"])
        self.assertEqual(rules("cat <<-EOF\n\t$(x)\n\tEOF\n"), ["H1"])

    def test_h1_in_a_heredoc_inside_a_substitution(self):
        cmd = 'acmectl --note "$(cat <<EOF\nx ' + BT + "y" + BT + "\nEOF\n)\""
        self.assertEqual(sorted(set(rules(cmd))), ["H1", "T2"])

    def test_u1_unquoted_backtick(self):
        self.assertEqual(rules("V=" + BT + "date" + BT), ["U1"])

    def test_hash_inside_a_word_is_not_a_comment(self):
        """PR 301 review: '#' starts a comment only at a word start. An escaped space, a
        backslash-newline or a closing $( ) continues the word, so the text after it is scanned."""
        for cmd in ["printf '%s\\n' word\\ # \"$(step-one)\"",
                    "printf '%s\\n' word\\\n# \"$(step-one)\"",
                    "V=$(step-one)#\"$(step-two)\"",
                    "e " + BT + "step-one" + BT + "#\"$(step-two)\""]:
            with self.subTest(cmd=cmd):
                self.assertIn("T2", rules(cmd))

    def test_hash_at_a_word_start_is_a_comment(self):
        for cmd in ["printf x # \"$(step-one)\"", "printf x \\\n# \"$(step-one)\"", "# \"$(step-one)\"",
                    "e $(step-one # c\n)"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(G.check(cmd), [])

    def test_ansi_c_and_locale_heredoc_delimiters(self):
        """PR 301 review: <<$'EOF' ends at a line EOF, and its body is quoted (not expanded)."""
        hidden = "cat <<$'EOF'\ntext\nEOF\nprintf '%s\\n' \"$(step-one)\"\n$EOF\n"
        self.assertEqual(rules(hidden), ["T2"])
        self.assertEqual(rules(hidden.replace("$'EOF'", '$"EOF"')), ["T2"])
        self.assertEqual(G.check("cat <<$'EOF'\n$(step-one) " + BT + "x" + BT + "\nEOF\n"), [])
        self.assertEqual(G.check('cat <<$"EOF"\n$(step-one)\nEOF\n'), [])
        self.assertIn("X1", rules("cat <<$'E\\tOF'\nx\nE\tOF\n"))  # an escape inside: not modelled
        self.assertIn("X1", rules("cat <<$'EOF\nx\n"))  # unterminated quote

    def test_double_quotes_nested_in_a_substitution_are_their_own_context(self):
        cmd = 'V=$(acmectl "' + BT + "x" + BT + '")'
        self.assertEqual(rules(cmd), ["D1"])


class Allowed(unittest.TestCase):
    CASES = [
        "V=$(git rev-parse --short HEAD)",
        'acmectl --subject "build $V" --body-file /abs/body.md',
        'printf \'%s\\n\' "$V" >> /abs/body.md',
        "echo 'a " + BT + "x" + BT + " $(y) b'",
        "echo $'tab\\t" + BT + "x" + BT + "'",
        'echo "\\$(x) and \\' + BT + 'y\\' + BT + '"',
        "cat >| /abs/b.txt <<'EOF'\nrun " + BT + "x" + BT + " and $(y)\nEOF\n",
        'cat <<"EOF"\n$(x)\nEOF\n',
        "cat <<\\EOF\n$(x)\nEOF\n",
        "cat <<E'O'F\n$(x)\nEOF\n",
        "cat <<EOF\nplain $V and ${W} only\nEOF\n",
        "ls # a comment with " + BT + "x" + BT + " and $(y)",
        "(( x << 2 )); echo $x",
        "echo $(( 1 + 2 ))",
        "cmd $(other) | grep x",
        "git commit -F /abs/msg.txt",
        "acmectl send --body-file '/abs/body.txt'",
        "cat <<<'here string " + BT + "x" + BT + "'",
        "",
    ]

    def test_inert_and_code_forms_are_allowed(self):
        for cmd in self.CASES:
            with self.subTest(cmd=cmd):
                self.assertEqual(G.check(cmd), [])


class NewConsumer(unittest.TestCase):
    """The same constructs under invented CLIs and flags: no rule may depend on a CLI name."""
    CLIS = ["acmectl post --note", "zz-notify --msg", "frobnicate -T", "x"]

    def test_every_rule_fires_for_an_unknown_cli(self):
        for cli in self.CLIS:
            with self.subTest(cli=cli):
                self.assertEqual(rules(cli + ' "a ' + BT + "q" + BT + '"'), ["D1"])
                self.assertEqual(rules(cli + ' "a $(q)"'), ["T2"])
                self.assertEqual(rules(cli + " " + BT + "q" + BT), ["U1"])
                self.assertEqual(rules(cli + " \"$(cat <<EOF\n$(q)\nEOF\n)\""), ["T2", "H1"])


class Bounds(unittest.TestCase):
    def test_unterminated_constructs_refuse(self):
        for cmd in ['echo "open', "echo 'open", "echo $(open", "echo " + BT + "open",
                    "echo ${open", "cat <<EOF\nno delimiter\n", "cat <<", "cat <<EOF"]:
            with self.subTest(cmd=cmd):
                self.assertIn("X1", rules(cmd))

    def test_oversize_input_refuses(self):
        self.assertEqual(rules("a" * (G.MAX_BYTES + 1)), ["B1"])

    def test_the_bound_counts_utf8_bytes_not_characters(self):
        two_byte = chr(0xE9)  # LATIN SMALL LETTER E WITH ACUTE: one character, two UTF-8 bytes
        self.assertEqual(G.check(two_byte * (G.MAX_BYTES // 2)), [])
        self.assertEqual(rules(two_byte * (G.MAX_BYTES // 2) + "a"), ["B1"])
        self.assertLess(len(two_byte * (G.MAX_BYTES // 2) + "a"), G.MAX_BYTES)  # under the bound in characters

    def test_deep_nesting_refuses(self):
        cmd = "$(" * (G.MAX_DEPTH + 1) + ")" * (G.MAX_DEPTH + 1)
        self.assertIn("B2", rules(cmd))

    def test_findings_are_capped(self):
        cmd = " ".join(['"' + BT + "x" + BT + '"'] * (G.MAX_FINDINGS * 3))
        self.assertEqual(len(G.check(cmd)), G.MAX_FINDINGS)


class KnownLimits(unittest.TestCase):
    """Pinned: these are ALLOWED today. A change here must be deliberate."""

    def test_second_parsers_are_not_read(self):
        for cmd in ["sh -c '" + BT + "x" + BT + "'", 'eval "$CMD"', "bash <<'EOF'\n" + BT + "x" + BT + "\nEOF\n",
                    "ssh host 'echo $(x)'", "python3 -c 'import os'", "bash ./script.sh"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(G.check(cmd), [])


class PayloadRoutes(unittest.TestCase):
    def test_shell_string_is_scanned(self):
        rc, err = decide(bash('acmectl --body "' + BT + 'x' + BT + '"'))
        self.assertEqual(rc, 2)
        self.assertIn("D1", err)
        self.assertIn("--body-file", err)

    def test_allowed_command_prints_nothing(self):
        self.assertEqual(decide(bash("git status")), (0, ""))

    def test_non_command_tools_pass(self):
        for payload in [{"tool_name": "Write", "tool_input": {"file_path": "/a", "content": '"' + BT + 'x' + BT + '"'}},
                        {"tool_name": "Read", "tool_input": {"file_path": "/a"}},
                        {"tool_name": "Bash"}, {"tool_name": "X", "tool_input": "text"}]:
            with self.subTest(payload=payload):
                self.assertEqual(decide(payload), (0, ""))

    def test_direct_argv_elements_are_inert(self):
        p = {"tool_input": {"command": ["acmectl", "send", "--body", "run " + BT + "x" + BT + " $(y)"]}}
        self.assertEqual(decide(p), (0, ""))

    def test_argv_is_never_joined_into_a_shell_string(self):
        # Joined, these words would read as an unquoted backtick; as argv they are inert.
        p = {"tool_input": {"cmd": ["printf", "%s", BT, "x", BT]}}
        self.assertEqual(decide(p), (0, ""))

    def test_shell_dash_c_script_operand_is_scanned(self):
        """argv[0] is the shell; its options are parsed by that shell's grammar."""
        for argv in [["bash", "-lc", 'acmectl --body "$(x)"'],
                     ["/bin/zsh", "-c", 'e "' + BT + 'x' + BT + '"'],
                     ["sh", "-e", "-o", "pipefail", "-c", "V=" + BT + "x" + BT],
                     ["bash", "-eo", "pipefail", "-c", "cat <<EOF\n$(x)\nEOF\n", "arg0"],
                     ["bash", "--norc", "--noprofile", "-c", 'e "$(x)"'],
                     ["bash", "--rcfile", "/abs/rc", "-c", 'e "$(x)"'],
                     ["bash", "-O", "extglob", "-c", 'e "$(x)"'],
                     ["zsh", "--emulate", "sh", "-c", 'e "$(x)"'],
                     ["zsh", "--no-rcs", "-c", 'e "$(x)"'],
                     ["dash", "-c", 'e "$(x)"']]:
            with self.subTest(argv=argv):
                rc, err = decide({"tool_input": {"command": argv}})
                self.assertEqual(rc, 2)
                self.assertRegex(err, r"\b(D1|T2|H1|U1)\b")

    def test_option_arguments_are_not_mistaken_for_the_script(self):
        # -o consumes "pipefail"; the script is the next operand, which is clean.
        p = {"tool_input": {"command": ["bash", "-o", "pipefail", "-c", "true", '"' + BT + 'x' + BT + '"']}}
        self.assertEqual(decide(p), (0, ""))

    def test_shell_dash_c_positional_args_are_inert(self):
        p = {"tool_input": {"command": ["bash", "-c", 'printf "%s" "$1"', "arg0", '"' + BT + 'x' + BT + '"']}}
        self.assertEqual(decide(p), (0, ""))

    def test_a_shell_named_as_an_ordinary_argument_is_inert(self):
        for argv in [["echo", "bash", "-c", 'e "' + BT + 'x' + BT + '"'],
                     ["grep", "-r", "sh -c", "."],
                     ["printf", "%s\\n", "zsh", "-c", "$(x)"]]:
            with self.subTest(argv=argv):
                self.assertEqual(decide({"tool_input": {"command": argv}}), (0, ""))

    def test_a_shell_reading_a_file_or_stdin_is_a_known_limit(self):
        for argv in [["bash", "./script.sh"], ["bash", "-s"], ["zsh"], ["sh", "--", "-c"]]:
            with self.subTest(argv=argv):
                self.assertEqual(decide({"tool_input": {"command": argv}}), (0, ""))

    def test_unmodelled_forms_refuse_visibly(self):
        for value, rule in [({"a": 1}, "P1"), (7, "P1"), ([], "P1"), (["ok", 3], "P1"),
                            (["bash", "-c"], "P2"), (["bash", "--frobnicate", "-c", "true"], "P2"),
                            (["dash", "--norc", "-c", "true"], "P2"), (["bash", "-1", "-c", "true"], "P2"),
                            (["fish", "-c", "echo"], "P3"), (["/usr/bin/csh", "x.csh"], "P3"),
                            (["env", "A=1", "sh", "-c", "true"], "P4"),
                            (["timeout", "5", "bash", "-c", "true"], "P4"),
                            (["sudo", "-u", "x", "/bin/zsh", "-c", "true"], "P4")]:
            with self.subTest(value=value):
                rc, err = decide({"tool_input": {"command": value}})
                self.assertEqual(rc, 2)
                self.assertIn(rule, err)

    def test_a_wrapper_with_no_shell_is_a_direct_exec(self):
        self.assertEqual(decide({"tool_input": {"command": ["timeout", "5", "git", "status"]}}), (0, ""))

    def test_broken_hook_input_refuses_visibly(self):
        for raw in [b"not json", b"[1, 2]", b'{"tool_input": {"command": "\xff"}}']:
            with self.subTest(raw=raw):
                rc, err = decide_raw(raw)
                self.assertEqual(rc, 2)
                self.assertIn("P0", err)

    def test_stdin_bound_is_enforced_while_reading(self):
        class Counting(io.BytesIO):
            asked = []

            def read(self, size: "int | None" = -1):
                Counting.asked.append(size)
                return super().read(size)

        err = io.StringIO()
        rc = G.main(Counting(b" " * (G.MAX_BYTES * 4)), err)
        self.assertEqual(rc, 2)
        self.assertIn("P0", err.getvalue())
        self.assertEqual(Counting.asked, [G.MAX_BYTES + 1])  # one bounded read, never an unbounded one

    def test_input_at_the_byte_bound_is_read_whole(self):
        body = json.dumps(bash("true")).encode("utf-8")
        raw = body + b" " * (G.MAX_BYTES - len(body))
        self.assertEqual(len(raw), G.MAX_BYTES)
        self.assertEqual(decide_raw(raw), (0, ""))

    def test_a_text_stream_is_refused(self):
        err = io.StringIO()
        self.assertEqual(G.main(io.StringIO("{}"), err), 2)
        self.assertIn("P0", err.getvalue())

    def test_both_keys_are_read(self):
        p = {"tool_input": {"command": "true", "cmd": 'e "$(x)"'}}
        self.assertEqual(decide(p)[0], 2)


class Structure(unittest.TestCase):
    """REGRESSION DETECTION, not a proof of zero execution: the module's imports, and every name
    and attribute it calls, must stay inside reviewed allowlists (README.md gives the call graph).
    A new call, a new import or dynamic dispatch changes these sets and fails here for review."""
    CALLED_NAMES = {
        # this module's own functions and classes
        "Scanner", "_Frame", "_Stop", "Refusal", "_basename", "_zsh_long", "_reason",
        "check", "classify_argv", "command_texts", "main",
        # builtins: pure value operations and print-to-a-given-stream
        "all", "any", "bool", "frozenset", "isinstance", "len", "print", "reversed", "sum",
        "super", "type", "TypeError",
    }
    CALLED_ATTRIBUTES = {
        # Scanner methods
        "scan", "find", "push", "pop", "top", "has_dq_ancestor", "substitution", "dollar",
        "skip_single", "skip_ansi_c", "at_command_start", "step_code", "step_dq", "step_hdoc",
        "step_param", "step_arith", "heredoc_operator", "read_heredoc_bodies", "open_backtick", "__init__",
        # str / bytes / list / dict methods
        "startswith", "lstrip", "rstrip", "rsplit", "join", "isalpha", "isalnum", "encode",
        "decode", "count", "append", "extend", "get",
        # the only I/O and library calls: one bounded read, json parsing, the exit status
        "read", "loads", "exit",
    }

    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_text(encoding="utf-8"))

    def test_imports_are_exactly_json_and_sys(self):
        imports = sorted(a.name for n in ast.walk(self.tree) if isinstance(n, ast.Import) for a in n.names)
        self.assertEqual(imports, ["json", "sys"])
        self.assertFalse([n for n in ast.walk(self.tree) if isinstance(n, ast.ImportFrom)])

    def test_every_called_name_is_reviewed(self):
        called = {n.func.id for n in ast.walk(self.tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertEqual(called - self.CALLED_NAMES, set())

    def test_every_called_attribute_is_reviewed(self):
        called = {n.func.attr for n in ast.walk(self.tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertEqual(called - self.CALLED_ATTRIBUTES, set())

    def test_no_call_through_a_computed_callee(self):
        odd = [ast.dump(n.func)[:60] for n in ast.walk(self.tree)
               if isinstance(n, ast.Call) and not isinstance(n.func, (ast.Name, ast.Attribute))]
        self.assertEqual(odd, [])

    def test_no_dynamic_attribute_access(self):
        names = {n.id for n in ast.walk(self.tree) if isinstance(n, ast.Name)}
        self.assertEqual(names & {"getattr", "setattr", "globals", "locals", "vars", "eval", "exec",
                                  "compile", "__import__", "open", "__builtins__"}, set())


if __name__ == "__main__":
    unittest.main()
