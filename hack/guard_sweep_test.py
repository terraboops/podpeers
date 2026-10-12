#!/usr/bin/env python3
"""Tests for hack/guard-sweep.py, the tool every guard verdict here rests on.

They import the copy of the tool that sits beside this file, so the sweep
can mutate the tool in a scratch worktree and run them against the mutant.
Each test pins one decision: what counts as a guard, how it is disabled, and
how a run is judged.

  python3 hack/guard_sweep_test.py
"""
import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path, name="guard_sweep"):
    """The module at path, compiled from its source now. Not through the
    import system: its bytecode cache trusts a source's mtime (to the
    second) and size, and two mutants of the same size written within one
    second would run the first one's code."""
    mod = types.ModuleType(name)
    mod.__file__ = path
    with open(path) as f:
        exec(compile(f.read(), path, "exec"), mod.__dict__)
    return mod


gs = load(os.path.join(HERE, "guard-sweep.py"))

# A mutant that loops forever must not hang the sweep: give up loudly.
signal.alarm(300)


def tree(files):
    """A scratch directory holding files; returns its path."""
    d = tempfile.mkdtemp()
    for p, body in files.items():
        os.makedirs(os.path.join(d, os.path.dirname(p)), exist_ok=True)
        with open(os.path.join(d, p), "w") as f:
            f.write(body)
    return d


def span(line, s):
    return None if s is None else line[s[0]:s[1]]


class Loading(unittest.TestCase):
    def test_a_stale_bytecode_cache_is_never_what_runs(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "m.py")
        def write(v):
            with open(p, "w") as f:
                f.write(f"A = {v}\n")
            os.utime(p, (1_000_000_000, 1_000_000_000))  # same second, same size
        write(1)
        # A process importing it the usual way caches its bytecode, wherever
        # this interpreter keeps that cache.
        importer = ("import importlib.util as u, sys; s = u.spec_from_file_location('m', sys.argv[1]); "
                    "m = u.module_from_spec(s); s.loader.exec_module(m); print(m.A)")
        imported = lambda: subprocess.run([sys.executable, "-c", importer, p], capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(imported(), "1")
        write(2)
        self.assertEqual(imported(), "1", "precondition: the import system runs the stale bytecode")
        self.assertEqual(load(p, "m").A, 2)


class ShellLists(unittest.TestCase):
    def test_action_after_the_last_top_level_operator(self):
        for line, want in [
            ('[ -n "$X" ] || die "x"', ' die "x"'),
            ("a && b; c", " b"),
            ("a || b || c", " c"),
            ("a || b && c", " c"),
            ("x=1 && y", " y"),
        ]:
            self.assertEqual(span(line, gs.split_list(line)), want, line)

    def test_no_guard_inside_quotes_brackets_or_comments(self):
        for line in ['echo "a || b"', "echo 'a && b'", 'x "a\\" || b"', "f $(a || b)", "{ a || b; }",
                     "[[ a || b ]]", "a # b || c", "#!/bin/sh || x", "plain command"]:
            self.assertIsNone(gs.split_list(line), line)

    def test_an_already_tolerant_list_is_not_a_guard(self):
        for line in ["a || true", "a || :", "a ||", "a || true; b"]:
            self.assertIsNone(gs.split_list(line), line)

    def test_a_comment_after_code_ends_the_scan(self):
        self.assertEqual(span("a || b # c && d", gs.split_list("a || b # c && d")), " b ")
        self.assertIsNone(gs.split_list("a || true # why"))
        self.assertEqual(span("a || b; c # d", gs.split_list("a || b; c # d")), " b")

    def test_a_hash_inside_a_word_is_not_a_comment(self):
        self.assertEqual(span("a#b || c", gs.split_list("a#b || c")), " c")


class ShellCode(unittest.TestCase):
    def test_heredoc_and_multiline_quote_bodies_are_not_code(self):
        lines = ["cat <<'EOF'", "a || b", "EOF", "x='", "c || d", "'", "e || f",
                 "cat <<-END", "g || h", "END", 'y="a\\"', 'z || w"', "k || l"]
        self.assertEqual(gs.code_lines(lines), [True, False, False, True, False, False, True,
                                                True, False, False, True, False, True])

    def test_a_quote_in_a_comment_opens_nothing(self):
        self.assertEqual(gs.code_lines(["# it's", "a || b"]), [True, True])
        self.assertEqual(gs.code_lines(["x # it's", "a || b"]), [True, True])

    def test_a_here_string_is_not_a_heredoc(self):
        self.assertEqual(gs.code_lines(["a <<< x", "b || c", "x"]), [True, True, True])


class ShellCases(unittest.TestCase):
    def test_one_line_case_arms(self):
        line = 'case "$x" in a) ;; b|c) die y ;; *) exit 1 ;; esac'
        self.assertEqual([span(line, a) for a in gs.inline_arms(line)], ["die y", "exit 1"])
        self.assertEqual(gs.inline_arms("a) die ;;"), [])
        self.assertEqual(gs.inline_arms('case "$x" in'), [])

    def test_which_lines_are_guards(self):
        script = "\n".join([
            "#!/bin/bash",                      # 1
            "# a || b",                         # 2 comment
            "[ -n \"$X\" ] || die x",           # 3 list
            "if [ a ]; then",                   # 4 if
            "elif [ b ]; then",                 # 5 elif
            "fi",                               # 6
            "trap 'a || b' EXIT",               # 7 trap: no
            "  | grep x || true",               # 8 continuation: no
            "a | b || c",                       # 9 list
            'case "$1" in',                     # 10
            "  up) up ;;",                      # 11 arm
            "  *) usage ;;",                    # 12 default arm
            "  multi)",                         # 13 open arm
            "    x",                            # 14
            "    ;;",                           # 15
            "esac",                             # 16
            "solo) not-an-arm ;;",              # 17 outside a case
            'case "$y" in a) ;; *) die ;; esac',  # 18 one-line case
            "cat <<EOF",                        # 19
            "q || r",                           # 20 heredoc: no
            "EOF",                              # 21
            "",                                 # 22
            "if [ c ] && [ d ]; then x; fi",    # 23 if, not a list
        ])
        root = tree({"s.sh": script})
        with mock.patch.object(gs, "ROOT", root):
            got = [n for _, n, _ in gs.shell_guards("s.sh")]
        self.assertEqual(got, [3, 4, 5, 9, 11, 12, 13, (18, 0), 23])

    def test_nested_cases_count_their_depth(self):
        script = "\n".join(['case "$a" in', "  x)", '    case "$b" in', "      y) z ;;", "    esac", "    ;;",
                            "  w) v ;;", "esac", "after) not ;;"])
        root = tree({"s.sh": script})
        with mock.patch.object(gs, "ROOT", root):
            got = [n for _, n, _ in gs.shell_guards("s.sh")]
        self.assertEqual(got, [2, 4, 7])

    def test_each_shell_mutation(self):
        for line, want in [
            ("if [ a ]; then b; fi", "if false; then b; fi"),
            ("  elif [ a ]; then", "  elif false; then"),
            ('[ -n "$X" ] || die "x"', '[ -n "$X" ] || true'),
            ("a && b; c", "a && true; c"),
            ("  up) up ;;", "  up) : ;;"),
            ("  *) usage; exit 1 ;;", "  *) : ;;"),
            ("  multi)", "  " + gs.NEVER + ")"),
            ("  multi) # note", "  " + gs.NEVER + ")"),
        ]:
            self.assertEqual(gs.mutate_shell(line), want, line)


class JavaScript(unittest.TestCase):
    def conds(self, line):
        return [line[a:q] for a, q in gs.ternaries(line)]

    def test_ternary_conditions(self):
        for line, want in [
            ("const a = b ? c : d;", ["b "]),
            ("  return x && y ? 1 : 2;", ["x && y "]),
            ("f(a ? b : c)", ["a "]),
            ("const x = a == b ? 1 : 2", ["a == b "]),
            ("const x = a != b ? 1 : 2", ["a != b "]),
            ("const x = a <= b ? 1 : 2", ["a <= b "]),
            ("const x = a >= b ? 1 : 2", ["a >= b "]),
            ("const f = n => n.k ? 1 : 2", ["n.k "]),
            ("const o = { k: a ? 1 : 2 }", ["a "]),
            ("const o = [a ? 1 : 2]", ["a "]),
            ("g(x, a ? 1 : 2)", ["a "]),
            ("a; b ? 1 : 2", ["b "]),
            ("const x = a ? b : c ? d : e", ["a ", "c "]),
            ("const x = a ? (b ? c : d) : e", ["a ", "b "]),
            ("const x = f(a) ? 1 : 2", ["f(a) "]),
            ("const x = /a?b/.test(s) ? 1 : 2", ["/a?b/.test(s) "]),
            ("const s = `a? ${b ? 1 : 2} c?`", ["b "]),
            ("const s = `${ {a: 1}.a ? 1 : 2 }`", ["{a: 1}.a "]),
            ("const s = 'a ? b' + (c ? 1 : 2)", ["c "]),
            ("const s = \"a\\\" ? b\" + (c ? 1 : 2)", ["c "]),
            ("const s = `a\\` ? b` + (c ? 1 : 2)", ["c "]),
            ("const x = a?.b ?? c", []),
            ("x?.y", []),
            ("a ?? b", []),
            ("return(a) ? 1 : 2", ["(a) "]),
            ("noreturn ? 1 : 2", ["noreturn "]),
            ("x = y / 2 ? 1 : 0", ["y / 2 "]),
            ("const x = /a\\/b?/.test(s) ? 1 : 2", ["/a\\/b?/.test(s) "]),
        ]:
            self.assertEqual(self.conds(line), want, line)

    def test_code_mask(self):
        line = "a 'b' `c ${d} e` g"
        #       0123456789012345678
        want = {0: True, 2: False, 3: False, 4: False, 6: False, 9: False, 10: False, 11: True, 12: False,
                14: False, 15: False, 17: True}
        for i, v in want.items():
            self.assertEqual(gs.js_code_mask(line)[i], v, (i, line[i]))
        # an escaped character in template text is text, even a backtick
        self.assertEqual(gs.js_code_mask("`a\\`b`")[3], False)
        regex = "x = /f?/.test(s)"
        self.assertEqual([gs.js_code_mask(regex)[i] for i in (0, 4, 6, 7, 8)], [True, False, False, False, True])
        # an unterminated string or regex stays text to the end
        self.assertEqual(gs.js_code_mask("a 'b")[3], False)
        self.assertEqual(gs.js_code_mask("x = /a")[5], False)
        self.assertEqual(gs.js_code_mask("`a\\")[2], False)
        # a slash after an operand divides; one after an operator starts a regex
        self.assertTrue(gs.js_code_mask("a / b / c")[4])
        self.assertTrue(gs.js_code_mask("// note")[3])
        # braces inside a substitution do not end it
        self.assertEqual(gs.js_code_mask("`${ {a: 1} } x`")[13], False)

    def test_if_condition_span(self):
        for line, want in [("if (a(b)) x", "a(b)"), ('if (s === ")") {', 's === ")"'), ("} else if (x) {", "x"),
                           ("if (a 'b) c", None), ("if ('a\\'b' || c) d", "'a\\'b' || c")]:
            got = gs.js_cond(line)
            self.assertEqual(None if got is None else line[got[0]:got[1]], want, line)

    def test_which_lines_are_guards(self):
        page = "\n".join(["if (a) b();", "  const x = a && b;", "  return c || d && e;", "// a ? b : c",
                          "const t = p ? 1 : 2;", "if (u) v = w ? 1 : 2;", "if (x ok", "plain();"])
        root = tree({"p.html": page})
        with mock.patch.object(gs, "ROOT", root):
            got = [n for _, n, _ in gs.js_guards("p.html")]
        self.assertEqual(got, [1, (2, 0), (3, 0), (3, 1), (5, 0, "?"), 6, (6, 0, "?")])


class Go(unittest.TestCase):
    """Go is read by hack/gocond; the sweep names and applies what it lists."""

    CODE = "\n".join([
        "package x",                                  # 1
        "func f(a, b, c bool, n int) bool {",         # 2
        "\tif a {",                                  # 3
        "\t} else if b && c {",                      # 4
        "\t}",                                       # 5
        "\tswitch {",                                # 6
        "\tcase a, b:",                              # 7
        "\t}",                                       # 8
        "\tswitch n {",                              # 9
        "\tcase 1:",                                 # 10
        "\t\treturn a",                             # 11
        "\tdefault:",                                # 12
        "\t\treturn b",                             # 13
        "\t}",                                       # 14
        "\tfor n > 0 {",                             # 15
        "\t\tn--",                                  # 16
        "\t}",                                       # 17
        "\treturn a || b",                           # 18
        "}",
        "",
    ])

    def test_which_conditions_and_their_names(self):
        root = tree({"internal/x/x.go": self.CODE, "internal/x/x_test.go": "package x\nfunc t(a bool) { if a {\n}\n}\n",
                     "other/y.go": "package y\nfunc g(a bool) {\n\tif a {\n\t}\n}\n",
                     "cmd/z/z.go": "package main\nfunc main() {\n\tif true {\n\t}\n}\n",
                     "hack/gocond/g.go": "package main\nfunc h(a bool) {\n\tif a {\n\t}\n}\n"})
        with mock.patch.object(gs, "ROOT", root):
            got = {(f, n): t for f, n, t in gs.guards()}
        x = "internal/x/x.go"
        self.assertEqual(got, {
            ("cmd/z/z.go", (3, "if", 0)): "if true {",
            ("hack/gocond/g.go", (3, "if", 0)): "if a {",
            (x, (3, "if", 0)): "if a {",
            (x, (4, "if", 0)): "} else if b && c {",
            (x, (4, "boolop", 0)): "} else if b && c { [operator 1 flipped]",
            (x, (7, "case", 0)): "case a, b:",
            (x, (7, "case", 1)): "case a, b: [case 2]",
            (x, (10, "arm", 0)): "case 1: [arm removed]",
            (x, (15, "for", 0)): "for n > 0 { [loop condition forced false]",
            (x, (18, "boolop", 0)): "return a || b [operator 1 flipped]",
        })

    def test_names_of_later_conditions_on_a_line(self):
        self.assertEqual(gs.go_text("l", "if", 1), "l [if 2]")
        self.assertEqual(gs.go_text("l", "case", 1), "l [case 2]")
        self.assertEqual(gs.go_text("l", "if", 0), "l")
        self.assertEqual(gs.go_text("l", "for", 1), "l [loop condition forced false 2]")
        self.assertEqual(gs.go_text("l", "arm", 2), "l [arm removed 3]")
        self.assertEqual(gs.go_text("l", "boolop", 2), "l [operator 3 flipped]")

    def test_each_go_mutation(self):
        for key, line, want in [
            ((3, "if", 0), 3, "\tif false && (a) {"),
            ((4, "boolop", 0), 4, "\t} else if b || c {"),
            ((7, "case", 1), 7, "\tcase a, false && (b):"),
            ((15, "for", 0), 15, "\tfor false && (n > 0) {"),
            ((18, "boolop", 0), 18, "\treturn a && b"),
        ]:
            d = tree({"x.go": self.CODE})
            p = os.path.join(d, "x.go")
            orig = gs.mutate(p, key)
            self.assertEqual(open(p).read().split("\n")[line - 1], want, key)
            self.assertEqual("\n".join(orig), self.CODE)
        d = tree({"x.go": self.CODE})
        p = os.path.join(d, "x.go")
        gs.mutate(p, (10, "arm", 0))
        self.assertIn("\tcase 1:\nreturn b\n\tdefault:", open(p).read(), "the arm's values fall to the default")

    def test_the_helper_is_built_once(self):
        with mock.patch.object(gs, "GOCOND", []):
            d = tree({"x.go": "package x\nfunc f(a bool) { if a {\n} }\n"})
            gs.gocond(["x.go"], d)
            built = list(gs.GOCOND)
            gs.gocond(["x.go"], d)
            self.assertEqual(gs.GOCOND, built)


class Mutate(unittest.TestCase):
    def mutated(self, name, text, n):
        d = tree({name: text})
        p = os.path.join(d, name)
        orig = gs.mutate(p, n)
        self.assertEqual("\n".join(orig), text)
        return open(p).read()

    def test_javascript(self):
        self.assertEqual(self.mutated("p.html", "x\nif (a) b();", 2), "x\nif (false && (a)) b();")
        self.assertEqual(self.mutated("p.html", "const x = a && b;", (1, 0)), "const x = a || b;")
        self.assertEqual(self.mutated("p.html", "const x = a ? 1 : 2;", (1, 0, "?")), "const x = (false && (a)) ? 1 : 2;")

    def test_shell(self):
        self.assertEqual(self.mutated("s.sh", "a || b", 1), "a || true")
        self.assertEqual(self.mutated("s.sh", "case x in a) b ;; *) c ;; esac", (1, 1)), "case x in a) b ;; *) : ;; esac")
        self.assertEqual(self.mutated("Makefile", "\t@a || (echo; exit 1)", 1), "\t@a || true")

    def test_workflow(self):
        y = "on:\n  push:\n    branches: [main]\n  pull_request:\n      - run: A=1 B=1 make x\n          fetch-depth: 0 # why"
        self.assertIn('      - run: "true"', self.mutated("c.yml", y, (5, 0, "run")))
        self.assertIn("      - run: B=1 make x", self.mutated("c.yml", y, (5, 0, "env")))
        self.assertIn("      - run: A=1 make x", self.mutated("c.yml", y, (5, 1, "env")))
        self.assertIn("fetch-depth: 1 # why", self.mutated("c.yml", y, (6, 0, "depth")))
        self.assertIn("branches: [never-a-branch]", self.mutated("c.yml", y, (3, 0, "trigger")))
        self.assertIn("  workflow_dispatch:", self.mutated("c.yml", y, (4, 0, "trigger")))

    def test_python(self):
        src = "x = 1\nif a and b:\n    y = c if d else e\nz = [v for v in w if v]\nwhile q or r:\n    pass\n"
        self.assertIn("if (False and (a and b)):", self.mutated("t.py", src, (2, "test", 0)))
        self.assertIn("if ((a) or (b)):", self.mutated("t.py", src, (2, "boolop", 0)))
        self.assertIn("y = c if (False and (d)) else e", self.mutated("t.py", src, (3, "test", 0)))
        self.assertIn("for v in w if (False and (v))]", self.mutated("t.py", src, (4, "test", 0)))
        self.assertIn("while (False and (q or r)):", self.mutated("t.py", src, (5, "test", 0)))
        self.assertIn("while ((q) and (r)):", self.mutated("t.py", src, (5, "boolop", 0)))

    def test_python_columns_count_bytes(self):
        src = 'x = "é→" if a else b\n'
        self.assertEqual(self.mutated("t.py", src, (1, "test", 0)), 'x = "é→" if (False and (a)) else b\n')

    def test_python_keys_count_per_line_and_kind(self):
        src = "x = a if b else (c if d else e)\ny = (f or g) and h\n"
        keys = [k for k, _ in gs.py_keyed(src)]
        self.assertEqual(keys, [(1, "test", 0), (1, "test", 1), (2, "boolop", 0), (2, "boolop", 1)])
        root = tree({"t.py": src})
        with mock.patch.object(gs, "ROOT", root):
            texts = [t for _, _, t in gs.py_guards("t.py")]
        self.assertEqual(texts[1], "x = a if b else (c if d else e) [condition forced false 2]")
        self.assertEqual(texts[2], "y = (f or g) and h [and/or flipped 1]")


class EmbeddedShell(unittest.TestCase):
    def test_only_lines_wholly_inside_a_raw_string_are_shell(self):
        code = "\n".join([
            "package p",                                  # 1
            "func s() string {",                          # 2
            "\tif a || b {",                             # 3 Go, not here
            "\ts := `[ -n q ] || die",                   # 4 opens the string: half Go, not shell
            "[ -n x ] || die",                            # 5 shell guard
            "if [ y ]; then",                             # 6 shell if
            "  if z; then :; fi",                         # 7 shell if
            "echo x",                                     # 8 (a raw string holds no backtick)
            "a && b; c",                                  # 9 shell guard
            "| grep q || true",                           # 10 not a guard
            "[ -n r ] || die`",                           # 11 closes it: half Go, not shell
            "\tok := c || d",                            # 12 Go again
            "}",
        ])
        root = tree({"p.go": code})
        with mock.patch.object(gs, "ROOT", root):
            got = [n for _, n, _ in gs.embedded_guards("p.go")]
        self.assertEqual(got, [(5, "sh"), (6, "sh"), (7, "sh"), (9, "sh")])

    def test_mutated_as_shell(self):
        d = tree({"p.go": "x\n[ -n a ] || die\nif [ b ]; then\n"})
        p = os.path.join(d, "p.go")
        orig = gs.mutate(p, (2, "sh"))
        self.assertEqual(open(p).read(), "x\n[ -n a ] || true\nif [ b ]; then\n")
        self.assertEqual("\n".join(orig), "x\n[ -n a ] || die\nif [ b ]; then\n")
        open(p, "w").write("\n".join(orig))
        gs.mutate(p, (3, "sh"))
        self.assertEqual(open(p).read(), "x\n[ -n a ] || die\nif false; then\n")


class Workflow(unittest.TestCase):
    def test_which_lines_are_guards(self):
        y = "\n".join(["on:", "  push:", "    branches: [main]", "  pull_request:", "jobs:", "  a:", "    steps:",
                       "      - uses: actions/checkout@v4", "        with:", "          fetch-depth: 0 # why",
                       "      - run: X=1 Y=1 make t", "      - name: n", "        run: make u", "          fetch-depth: 1",
                       "    branches: [dev]"])
        root = tree({"c.yml": y})
        with mock.patch.object(gs, "ROOT", root):
            got = [n for _, n, _ in gs.wf_guards("c.yml")]
        self.assertEqual(got, [(3, 0, "trigger"), (4, 0, "trigger"), (10, 0, "depth"), (11, 0, "run"),
                               (11, 0, "env"), (11, 1, "env"), (13, 0, "run")])


class Verdicts(unittest.TestCase):
    """run() judges each mutant by the command's outcome."""

    def judge(self, f, script, cmd=None):
        body = "if (a) b();\n" if f.endswith(".html") else "a || b\n"
        root = tree({f: body, "hack/check-ui.sh": "#!/bin/sh\n" + script, "t.sh": "#!/bin/sh\n" + script})
        os.chmod(os.path.join(root, "hack/check-ui.sh"), 0o755)
        os.chmod(os.path.join(root, "t.sh"), 0o755)
        with mock.patch.object(gs, "worktree", lambda: root), mock.patch.object(gs.subprocess, "run"), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            res = gs.run([(f, 1, body.strip())], cmd or (lambda _: ["./t.sh"]))
        self.assertEqual(open(os.path.join(root, f)).read(), body, "the mutant must be undone")
        return res[0][0], err.getvalue()

    def test_pass_is_survived_and_failure_is_noticed(self):
        self.assertEqual(self.judge("x.sh", "exit 0")[0], True)
        self.assertEqual(self.judge("x.sh", "exit 1")[0], False)

    def test_a_timeout_is_a_hang_unless_the_script_cannot_hang(self):
        hang = "echo 'panic: test timed out after 5m'; exit 1"
        survived, err = self.judge("x.sh", hang)
        self.assertEqual((survived, "a hang: noticed" in err), (False, True))
        with mock.patch.object(gs, "NO_HANGS", {"slow.sh"}):
            survived, err = self.judge("slow.sh", hang)
        self.assertEqual((survived, "NOT counted as noticed" in err), (True, True))
        with mock.patch.object(gs, "NO_HANGS", {"slow.sh"}):
            self.assertEqual(self.judge("slow.sh", "exit 1")[0], False)

    def test_a_browser_check_must_judge(self):
        ui = lambda _: ["./hack/check-ui.sh"]
        self.assertEqual(self.judge("p.html", "echo 'FAIL  x'; exit 1", ui)[0], False)
        survived, err = self.judge("p.html", "echo boom; exit 1", ui)
        self.assertEqual((survived, "no verdict" in err), (True, True))
        self.assertEqual(self.judge("p.html", "echo 'xFAIL x'; exit 1", ui)[0], True)
        self.assertEqual(self.judge("p.html", "echo boom; exit 1")[0], False, "other commands judge by exit code")

    def test_a_mutant_the_build_rejects_is_named(self):
        survived, err = self.judge("x.sh", "echo 'FAIL\tx [build failed]'; exit 1")
        self.assertEqual((survived, "does not compile" in err), (False, True))
        survived, err = self.judge("x.sh", "echo 'FAIL\tx [setup failed]'; exit 1")
        self.assertEqual((survived, "does not compile" in err), (False, True))
        survived, err = self.judge("x.sh", "echo 'FAIL\tx'; exit 1")
        self.assertNotIn("does not compile", err, "a test failure is not a build failure")
        survived, err = self.judge("x.sh", "echo 'ok [build failed] in a test name'; exit 0")
        self.assertEqual((survived, "does not compile" in err), (True, False))

    def test_a_mutant_cannot_outlive_its_run(self):
        pidfile = os.path.join(tempfile.mkdtemp(), "pid")
        self.judge("x.sh", f"sleep 60 >/dev/null 2>&1 & echo $! > {pidfile}; exit 0")
        pid = int(open(pidfile).read())
        # Killed is gone, or a zombie not yet reaped; on a loaded machine
        # either can take a moment, so wait for it rather than guess.
        def alive():
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            stat = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
            return bool(stat.strip()) and not stat.strip().startswith("Z")
        deadline = time.time() + 10
        while alive() and time.time() < deadline:
            time.sleep(0.05)
        self.assertFalse(alive(), "the mutant's child outlived its run")

    def test_each_mutants_output_can_be_kept(self):
        logs = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"GUARD_SWEEP_LOG": logs}):
            self.judge("x.sh", "echo the-test-said-this; exit 1")
        files = os.listdir(logs)
        self.assertEqual(len(files), 1)
        body = open(os.path.join(logs, files[0])).read()
        self.assertIn("the-test-said-this", body)
        self.assertIn("exit 1", body)
        self.assertTrue(files[0].startswith("x.sh_1"), files)

    def test_parallel_runs_every_item_once(self):
        seen = []
        def run(items, cmd):
            seen.extend(items)
            return [(True, f, n, t) for f, n, t in items]
        with mock.patch.object(gs, "run", run):
            out = gs.parallel([("a", i, "t") for i in range(13)], None, workers=4)
        self.assertEqual(sorted(seen), sorted(("a", i, "t") for i in range(13)))
        self.assertEqual(len(out), 13)


class Check(unittest.TestCase):
    ACCEPTED = "\n".join(["# header", "", "x.go | if a { | error | why",
                          "x.go | if a { | error | a second, identical guard",
                          "internal/render/page.html | if (b) { | cosmetic | why",
                          "hack/check-ui.sh | c || d | cosmetic | why",
                          "w.yml | run: curl x | sh [step's command replaced by true] | setup | why"]) + "\n"

    def check(self, left, browser, only=False):
        root = tree({"hack/guard-sweep-accepted.txt": self.ACCEPTED})
        with mock.patch.object(gs, "ROOT", root), contextlib.redirect_stderr(io.StringIO()) as err:
            return gs.check(left, browser, only), err.getvalue()

    go = [("x.go", 1, "if a {"), ("x.go", 9, "if a {"), ("w.yml", (3, 0, "run"), "run: curl x | sh [step's command replaced by true]")]
    br = [("internal/render/page.html", 2, "if (b) {"), ("hack/check-ui.sh", 3, "c || d")]

    def test_every_survivor_accepted_and_every_entry_surviving(self):
        self.assertEqual(self.check(self.go, False)[0], 0)
        self.assertEqual(self.check(self.go + self.br, True)[0], 0)
        self.assertEqual(self.check(self.br, True, only=True)[0], 0)

    def test_an_unaccounted_survivor_fails(self):
        code, err = self.check(self.go + [("y.go", (4, 0), "z [operator 1 flipped]")], False)
        self.assertEqual(code, 1)
        self.assertIn("UNACCOUNTED  y.go:4: z [operator 1 flipped]", err)

    def test_a_stale_entry_fails(self):
        code, err = self.check(self.go[:1], False)
        self.assertEqual(code, 1)
        self.assertIn("STALE        x.go: if a {", err)

    def test_go_and_the_rest_are_checked_apart(self):
        sh = [("hack/x.sh", 1, "a || b")]
        root = tree({"hack/guard-sweep-accepted.txt": self.ACCEPTED + "hack/x.sh | a || b | equivalent | why\n"})
        with mock.patch.object(gs, "ROOT", root), contextlib.redirect_stderr(io.StringIO()):
            gonly = [g for g in self.go if g[0].endswith(".go")]
            self.assertEqual(gs.check(gonly, False, go=True, scripts=False), 0, "Go alone: the script entries are not checked")
            rest = sh + [g for g in self.go if not g[0].endswith(".go")]
            self.assertEqual(gs.check(rest, False, go=False, scripts=True), 0, "scripts alone: the Go entries are not checked")
            self.assertEqual(gs.check(rest, False, go=True, scripts=True), 1, "both: the Go entries must survive too")

    def test_only_what_was_swept_is_checked(self):
        self.assertEqual(self.check(self.go + self.br, False)[0], 1, "unswept browser survivors are unaccounted")
        self.assertEqual(self.check(self.go, True)[0], 1, "browser entries are checked with --browser")
        self.assertEqual(self.check(self.go + self.br, True, only=True)[0], 1, "Go survivors are unaccounted with --browser-only")
        self.assertEqual(self.check([], True, only=True)[0], 1, "browser entries are still checked with --browser-only")


def cmds_first(calls):
    """Each file's command in the first sweep call that holds it."""
    out = {}
    for files, _, cs in calls:
        for f, c in zip(files, cs):
            out.setdefault(f, c)
    return out


class Main(unittest.TestCase):
    """main() sweeps what it is asked to, in the order it must."""

    def sweep(self, argv, baseline_ok=True, dirty=""):
        calls = []
        def parallel(items, cmd, workers=6):
            calls.append(([i[0] for i in items], workers, [cmd(i[0]) for i in items]))
            return [(True, f, n, t) for f, n, t in items]
        found = {"guards": [("internal/x.go", 1, "if a {")],
                 "shell": lambda rel: [(rel, 1, "a || b")],
                 "wf": lambda rel: [(rel, (1, 0, "run"), "run: x")],
                 "py": lambda rel: [(rel, (1, "test", 0), "if x:")],
                 "js": lambda rel: [(rel, 1, "if (a) {")],
                 "emb": lambda rel: [(rel, (1, "sh"), "a || b [embedded shell]")]}
        def fake_run(args, **kw):
            if "status" in args:
                return subprocess.CompletedProcess(args, 0, dirty, "")
            return subprocess.CompletedProcess(args, 0 if baseline_ok else 1, "", "")
        run = mock.Mock(side_effect=fake_run)
        with mock.patch.object(gs, "parallel", parallel), mock.patch.object(gs, "guards", lambda: found["guards"]), \
                mock.patch.object(gs, "shell_guards", found["shell"]), mock.patch.object(gs, "wf_guards", found["wf"]), \
                mock.patch.object(gs, "py_guards", found["py"]), mock.patch.object(gs, "js_guards", found["js"]), \
                mock.patch.object(gs, "embedded_guards", found["emb"]), \
                mock.patch.object(gs, "worktree", lambda: "/nonexistent"), mock.patch.object(gs.subprocess, "run", run), \
                mock.patch.object(gs, "check", lambda left, b, o=False, go=None, scripts=None: ("checked", len(left), b, o, go, scripts)), \
                mock.patch.object(sys, "argv", ["guard-sweep.py"] + argv), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                gs.main()
                code = None
            except SystemExit as e:
                code = e.code
        return calls, code, run, out.getvalue(), err.getvalue()

    def test_the_default_sweep_leaves_the_browser_out(self):
        calls, code, run, out, err = self.sweep([])
        swept = [f for files, _, _ in calls for f in files]
        self.assertIn("internal/x.go", swept)
        self.assertIn("hack/hygiene.sh", swept)
        self.assertIn(".github/workflows/ci.yml", swept)
        self.assertIn("hack/guard-sweep.py", swept)
        self.assertIn("internal/procnet/procnet.go", swept)
        self.assertNotIn("internal/render/page.html", swept)
        self.assertNotIn("hack/check-ui.sh", swept)
        self.assertEqual([c for c in run.call_args_list if c.args[0][0].startswith("./hack/")], [], "no browser baseline without --browser")
        self.assertIsNone(code)
        self.assertIn("internal/x.go:1: if a {", out)
        self.assertIn(".github/workflows/ci.yml:1: run: x", out, "a survivor keyed by a tuple prints its line")
        self.assertIn("survive their tests", err)

    def test_slow_scripts_run_two_at_a_time_and_the_browser_one(self):
        calls, *_ = self.sweep(["--browser"])
        by = {f: w for files, w, _ in calls for f in files}
        self.assertEqual(by["hack/hygiene.sh"], 2)
        self.assertEqual(by["skills/podpeers-netpol/scripts/netpol-check.sh"], 6)
        self.assertEqual(by["internal/render/page.html"], 1)
        self.assertEqual(by["hack/check-ui.sh"], 1)
        cmds = {f: c for files, _, cs in calls for f, c in zip(files, cs) if f not in cmds_first(calls)} | cmds_first(calls)
        self.assertEqual(cmds["internal/render/page.html"], ["./hack/check-ui.sh"])
        self.assertEqual(cmds[".github/workflows/ci.yml"][-1], "./test/tooling/")
        self.assertEqual(cmds["hack/guard-sweep.py"], ["python3", "hack/guard_sweep_test.py"])
        self.assertEqual(cmds["internal/procnet/procnet.go"][-1], "./internal/procnet/")
        self.assertEqual(cmds["internal/x.go"], ["go", "test", "-count=1", "./internal/"])
        whole = [cs for files, _, cs in calls if "internal/x.go" in files][1]
        self.assertEqual(whole, [["go", "test", "-count=1", "./internal/...", "./cmd/...", "./test/skillscript/", "./hack/gocond/"]],
                         "a survivor of its package's tests faces the whole unit suite")

    def test_browser_only_sweeps_only_the_browser(self):
        calls, code, run, out, err = self.sweep(["--browser-only", "--check"])
        swept = [f for files, _, _ in calls for f in files]
        self.assertEqual(sorted(set(swept)), ["hack/check-docs.sh", "hack/check-ui.sh", "internal/render/page.html"])
        self.assertEqual(code, ("checked", 3, True, True, False, False))
        baselines = [c.args[0] for c in run.call_args_list if c.args[0][0].startswith("./hack/")]
        self.assertEqual(sorted(baselines), [["./hack/check-docs.sh"], ["./hack/check-ui.sh"]], "both browser checks run unmutated first")

    def test_check_gets_the_scope(self):
        self.assertEqual(self.sweep(["--check"])[1][2:], (False, False, True, True))
        self.assertEqual(self.sweep(["--check", "--browser"])[1][2:], (True, False, True, True))
        self.assertEqual(self.sweep(["--check", "--go-only"])[1][2:], (False, False, True, False))
        self.assertEqual(self.sweep(["--check", "--scripts-only"])[1][2:], (False, False, False, True))

    def test_go_only_and_scripts_only_split_the_sweep(self):
        go = {f for files, _, _ in self.sweep(["--go-only"])[0] for f in files}
        scripts = {f for files, _, _ in self.sweep(["--scripts-only"])[0] for f in files}
        self.assertEqual(go, {"internal/x.go"})
        self.assertNotIn("internal/x.go", scripts)
        self.assertIn("hack/hygiene.sh", scripts)
        self.assertIn("internal/procnet/procnet.go", scripts, "embedded shell goes with the scripts")
        self.assertNotIn("internal/render/page.html", go | scripts)
        for split in ("--go-only", "--scripts-only"):
            both = {f for files, _, _ in self.sweep(["--browser", split])[0] for f in files}
            self.assertNotIn("internal/render/page.html", both, f"--browser {split}: the browser guards are a job of their own")

    def test_a_dirty_tree_is_refused(self):
        calls, code, run, out, err = self.sweep(["--check"], dirty=" M Makefile\n")
        self.assertEqual((calls, code), ([], 2))
        self.assertIn("commit first", err)
        self.assertIn("M Makefile", err)

    def test_a_failing_browser_baseline_stops_everything(self):
        calls, code, run, out, err = self.sweep(["--browser"], baseline_ok=False)
        self.assertEqual((calls, code), ([], 1))
        self.assertIn("fails unmutated; nothing swept", err)

    def test_e2e_mode_runs_each_listed_survivor_on_the_cluster(self):
        f = os.path.join(tempfile.mkdtemp(), "list")
        with open(f, "w") as fh:
            fh.write("internal/x.go:12: if a {\n")
        got = {}
        def run(items, cmd, env):
            got.update(items=items, cmd=cmd("internal/x.go"), env=env("/wt"))
            return [(False, "internal/x.go", 12, "if a {")]
        clean = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        with mock.patch.object(gs, "run", run), mock.patch.object(sys, "argv", ["g", "--e2e", f]), \
                mock.patch.object(gs.subprocess, "run", clean), contextlib.redirect_stdout(io.StringIO()) as out:
            gs.main()
        self.assertEqual(got["items"], [("internal/x.go", 12, "if a {")])
        self.assertIn("^TestE2E$", got["cmd"])
        self.assertEqual(got["env"]["PODPEERS_E2E_OUT"], "/wt/.e2e-out")
        self.assertIn("cluster-killed internal/x.go:12: if a {", out.getvalue())
        with mock.patch.object(gs, "run", lambda items, cmd, env: [(True, "internal/x.go", 12, "if a {")]), \
                mock.patch.object(gs.subprocess, "run", clean), \
                mock.patch.object(sys, "argv", ["g", "--e2e", f]), contextlib.redirect_stdout(io.StringIO()) as out:
            gs.main()
        self.assertIn("cluster-SURVIVED internal/x.go:12: if a {", out.getvalue())

    def test_run_as_a_script_it_runs(self):
        # Imported, nothing runs; run as CI runs it, main must.
        r = subprocess.run([sys.executable, os.path.join(HERE, "guard-sweep.py"), "--e2e", "/nonexistent/list"],
                           capture_output=True, text=True)
        # It refuses a dirty tree, or fails to read the list: either way main
        # ran. Not running at all would exit 0, silently.
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue("/nonexistent/list" in r.stderr or "commit first" in r.stderr, r.stderr)


if __name__ == "__main__":
    unittest.main()
