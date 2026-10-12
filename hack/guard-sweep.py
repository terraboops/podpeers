#!/usr/bin/env python3
"""Remove every guard, one at a time, and see whether any test notices.

Guards, each disabled one at a time in a scratch worktree of HEAD:

  Go (non-test code under internal/, cmd/ and hack/gocond), by its parser
    (hack/gocond): each if and for condition and tagless-switch case
    expression  ->  `false && (<c>)`; each && and ||  ->  flipped; each arm
    of a tagged or type switch  ->  the default arm's body (or none). A
    mutant the compiler rejects is noticed, by the build, and said so.
  Shell (the skill's script and hack/*.sh)
    `if <c>; then` / `elif <c>; then`    ->  condition `false`
    `while <c>; do` / `until <c>; do`     ->  a loop that never runs
    `<c> || <action>` / `<c> && <action>` lists  ->  action `true`
    a one-line `case` arm `<pat>) <body> ;;`, default arms included, and
      each arm of a one-line `case ... esac`  ->  body `:`
    a multi-line arm `<pat>)`  ->  a pattern that never matches (the arm is gone)
  Make recipes, and shell inside a Go raw string (the sampler): as for shell
  This tool (Python), by its AST, against hack/guard_sweep_test.py
    each if / elif / while test, conditional-expression test and
    comprehension filter  ->  `False and (<c>)`; each and / or  ->  flipped
  The CI workflow (.github/workflows/ci.yml), against what it declares
    each `run:` step  ->  `run: "true"`; each `X=1 ` flag in it  ->  dropped
    `fetch-depth: 0`  ->  1; the push and pull_request triggers  ->  removed
  JavaScript (the web UI, internal/render/page.html; with --browser)
    `if (<c>)`            ->  `if (false && (<c>))`
    each && or || in `return ...` or `x = ...`  ->  flipped, one at a time
    each ternary `<c> ? a : b`  ->  `(false && (<c>)) ? a : b`
    each `for (...; <c>; ...)` condition  ->  `false`

Go guards run that package's tests (fast), then, for survivors, the whole
unit suite. A shell guard runs the tests that drive that script (SHELL_TESTS).
What survives is a guard whose removal no test notices; each must be
accounted for in hack/guard-sweep-accepted.txt: caught on the real cluster
(--e2e measures it), or why it is not a finding.

  hack/guard-sweep.py              unit sweep; prints survivors
  hack/guard-sweep.py --browser    also the web UI's JavaScript and the browser
                                   checks' own guards, against the browser
                                   check (needs node and Chrome; slow)
  hack/guard-sweep.py --browser-only   only those (CI runs it as its own job)
  hack/guard-sweep.py --go-only        only the Go conditions
  hack/guard-sweep.py --scripts-only   only the rest: shell, Make, the
                                       workflow, this tool, embedded shell
  hack/guard-sweep.py --check      sweep, compared with
                                   hack/guard-sweep-accepted.txt: fails on a
                                   survivor nobody has accounted for, and on an
                                   accepted entry that no longer survives
  hack/guard-sweep.py --e2e FILE   for each survivor listed in FILE (lines as
                                   printed by the unit sweep), run the real-
                                   cluster TestE2E instead (needs make e2e-cluster)

Accepted entries are matched by file and guard text, not line number, so
edits elsewhere in a file do not invalidate them.
"""
import ast
import concurrent.futures
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
OP = re.compile(r"&&|\|\|")

# Go is read by its own parser (hack/gocond), built once per sweep.
GO_DIRS = ("internal", "cmd", os.path.join("hack", "gocond"))
GOCOND = []
GOCOND_LOCK = threading.Lock()


def gocond(paths, cwd):
    """hack/gocond's conditions for the Go files at paths (relative to cwd)."""
    with GOCOND_LOCK:
        if not GOCOND:
            out = os.path.join(tempfile.mkdtemp(), "gocond")
            here = os.path.dirname(os.path.abspath(__file__))  # this checkout's helper
            subprocess.run(["go", "build", "-o", out, "./gocond"], cwd=here, check=True)
            GOCOND.append(out)
    r = subprocess.run([GOCOND[0]] + list(paths), cwd=cwd, capture_output=True, text=True, check=True)
    return [json.loads(l) for l in r.stdout.splitlines()]


GO_LABELS = {"if": "if", "case": "case", "for": "loop condition forced false", "arm": "arm removed"}


def go_text(line, kind, k):
    """A Go condition's name in hack/guard-sweep-accepted.txt: the line, and
    for all but the first if or case on it, which one and how it is disabled."""
    if kind == "boolop":
        return f"{line} [operator {k + 1} flipped]"
    if kind in ("if", "case") and k == 0:
        return line
    return f"{line} [{GO_LABELS[kind]}]" if k == 0 else f"{line} [{GO_LABELS[kind]} {k + 1}]"

# The tests that drive each shell script. hygiene's get room: one equivalent
# mutant makes --history read every object, about 3x slower (see NO_HANGS).
# hack/check-docs.sh and hack/check-ui.sh are themselves the docs and browser
# checks: removing one of their guards is caught, or not, by running them
# (needs node and Chrome).
SHELL_TESTS = {
    "skills/podpeers-netpol/scripts/netpol-check.sh": ["go", "test", "-count=1", "-timeout", "5m", "./test/skillscript/"],
    "hack/hygiene.sh": ["go", "test", "-count=1", "-timeout", "60m", "./test/hygiene/"],
    "hack/e2e-cluster.sh": ["go", "test", "-count=1", "-timeout", "5m", "./test/tooling/"],
    "hack/mutants.sh": ["go", "test", "-count=1", "-timeout", "5m", "./test/tooling/"],
    "hack/check-docs.sh": ["./hack/check-docs.sh"],
    "hack/check-ui.sh": ["./hack/check-ui.sh"],
    # Make recipes are shell: their `cmd || (echo ...; exit 1)` checks and
    # `a && b` lists are swept like the scripts', against scratch Makefiles.
    "Makefile": ["go", "test", "-count=1", "-timeout", "5m", "./test/tooling/"],
    # Records the demo against .e2e/kubeconfig; its context check is tested.
    "docs/demo/make-demo.sh": ["go", "test", "-count=1", "-timeout", "5m", "./test/tooling/"],
}

# Shell that lives inside Go source, in a raw string: the sampler script
# each debug container runs. Its guards are shell, swept as shell, against
# the tests that run the script under sh.
EMBEDDED_SH = {"internal/procnet/procnet.go": ["go", "test", "-count=1", "-timeout", "3m", "./internal/procnet/"]}


def embedded_guards(rel):
    """Shell guards on the lines of a Go file's multi-line raw strings."""
    out, inside = [], False
    for i, l in enumerate(open(os.path.join(ROOT, rel)).read().split("\n")):
        was = inside
        if l.count("`") % 2:
            inside = not inside
        if not (was and inside):
            continue  # only lines wholly inside the string
        t = l.strip()
        if SH_IF.match(l) or (split_list(l) is not None and not t.startswith(("trap ", "if ", "elif ", "|"))):
            out.append((rel, (i + 1, "sh"), f"{t} [embedded shell]"))
    return out

# This tool itself: its tests import whichever copy sits beside them.
PY_TESTS = {"hack/guard-sweep.py": ["python3", "hack/guard_sweep_test.py"]}


def py_nodes(src):
    """Every condition in a Python source, by the AST: (kind, node), where
    kind is "test" (an if, elif or while test, a conditional expression's
    test, a comprehension filter) or "boolop" (an and / or expression)."""
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            out.append(("test", node.test))
        elif isinstance(node, ast.comprehension):
            out.extend(("test", c) for c in node.ifs)
        elif isinstance(node, ast.BoolOp):
            out.append(("boolop", node))
    return sorted(out, key=lambda x: (x[1].lineno, x[1].col_offset, x[0]))


def py_keyed(src):
    """Each condition keyed (line, kind, k): the k-th of its kind on its line."""
    seen, out = {}, []
    for kind, node in py_nodes(src):
        k = seen.get((node.lineno, kind), 0)
        seen[(node.lineno, kind)] = k + 1
        out.append(((node.lineno, kind, k), node))
    return out


def py_guards(rel):
    src = open(os.path.join(ROOT, rel)).read()
    lines = src.split("\n")
    names = {"test": "condition forced false", "boolop": "and/or flipped"}
    return [(rel, key, f"{lines[key[0] - 1].strip()} [{names[key[1]]} {key[2] + 1}]") for key, _ in py_keyed(src)]


def mutate_py(src, key):
    """src with the condition at key disabled: a test made False, an and/or
    flipped."""
    lines = src.split("\n")
    node = dict(py_keyed(src))[key]
    def at(line, col):  # AST columns count UTF-8 bytes
        return sum(len(l) + 1 for l in lines[:line - 1]) + len(lines[line - 1].encode()[:col].decode())
    a, b = at(node.lineno, node.col_offset), at(node.end_lineno, node.end_col_offset)
    if key[1] == "test":
        new = "(False and (" + src[a:b] + "))"
    else:
        op = " and " if isinstance(node.op, ast.Or) else " or "
        new = "(" + op.join("(" + src[at(v.lineno, v.col_offset):at(v.end_lineno, v.end_col_offset)] + ")" for v in node.values) + ")"
    return src[:a] + new + src[b:]


# The workflow cannot run here. What it declares can be checked, and is:
# each gate step, its fail-don't-skip flags, full history, its triggers.
WF_TESTS = {".github/workflows/ci.yml": ["go", "test", "-count=1", "-run", "TestWorkflowDeclaresEveryGate", "./test/tooling/"]}
WF_ENV = re.compile(r"\b[A-Z_]+=1 ")


def wf_guards(rel):
    out = []
    for i, l in enumerate(open(os.path.join(ROOT, rel)).read().split("\n")):
        t = l.strip()
        if t.startswith(("run:", "- run:")):
            out.append((rel, (i + 1, 0, "run"), f"{t} [step's command replaced by true]"))
            for k, m in enumerate(WF_ENV.finditer(l)):
                out.append((rel, (i + 1, k, "env"), f"{t} [{m.group().strip()} dropped]"))
        elif t == "fetch-depth: 0" or t.startswith("fetch-depth: 0 "):
            out.append((rel, (i + 1, 0, "depth"), f"{t} [made shallow]"))
        elif t in ("branches: [main]", "pull_request:"):
            out.append((rel, (i + 1, 0, "trigger"), f"{t} [trigger removed]"))
    return out


def mutate_wf(line, k, kind):
    if kind == "run":
        return line[:line.index("run:")] + 'run: "true"'
    if kind == "env":
        m = list(WF_ENV.finditer(line))[k]
        return line[:m.start()] + line[m.end():]
    if kind == "depth":
        return line.replace("fetch-depth: 0", "fetch-depth: 1", 1)
    return line.replace("branches: [main]", "branches: [never-a-branch]").replace("pull_request:", "workflow_dispatch:")
# The web UI's JavaScript runs only in a browser: its guards are swept with
# --browser, against the browser check.
JS_TESTS = {"internal/render/page.html": ["./hack/check-ui.sh"]}
JS_IF = re.compile(r"^\s*(\} else )?if \(")


def js_cond(line):
    """(start, end) of the condition inside a line's first `if (...)`."""
    i = line.index("if (") + 4
    depth, quote, j = 1, None, i
    while j < len(line):
        c = line[j]
        if quote:
            if c == "\\":
                j += 1
            elif c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i, j
        j += 1
    return None


# A JavaScript for loop's condition: `for (<init>; <c>; <step>)`.
JS_FOR = re.compile(r"\bfor \(([^;()]*);([^;()]+);")


JS_BOOL = re.compile(r"^\s*(return |(const |let )?[\w.]+ = ).*(&&|\|\|)")


def js_code_mask(line):
    """For each character of a JavaScript line: is it code (not inside a
    string, a template's text or a regex literal)?"""
    mask, stack, i = [True] * len(line), [], 0  # stack: "`" in template text, "{" in code
    def text():
        return stack and stack[-1] == "`"
    while i < len(line):
        c = line[i]
        if text():
            mask[i] = False
            if c == "\\":
                i += 1
                if i < len(line):
                    mask[i] = False
            elif c == "`":
                stack.pop()
            elif line.startswith("${", i):
                mask[i] = mask[i + 1] = False
                stack.append("${")
                i += 1
        elif c in "'\"":
            j = i + 1
            while j < len(line) and line[j] != c:
                j += 2 if line[j] == "\\" else 1
            for x in range(i, min(j + 1, len(line))):
                mask[x] = False
            i = j
        elif c == "`":
            mask[i] = False
            stack.append("`")
        elif c == "/" and re.match(r".*[=(,:!&|?]\s*$", line[:i]) and not line.startswith("//", i):
            j = i + 1  # a regex literal
            while j < len(line) and line[j] != "/":
                j += 2 if line[j] == "\\" else 1
            for x in range(i, min(j + 1, len(line))):
                mask[x] = False
            i = j
        elif c == "{" and stack and stack[-1] == "${":
            stack.append("{")
        elif c == "}" and stack and stack[-1] in ("{", "${"):
            if stack.pop() == "${":
                mask[i] = False
        i += 1
    return mask


def ternaries(line):
    """(start, ?) of the condition of each ternary in a JavaScript line: from
    its ? back to the nearest delimiter that binds more loosely than ?: (an
    unmatched bracket, a comma or semicolon, an assignment or arrow, return,
    or an enclosing ternary's ? or :)."""
    mask, out = js_code_mask(line), []
    for q, c in enumerate(line):
        if c != "?" or not mask[q] or line[q + 1:q + 2] in ("?", ".") or line[q - 1:q] == "?":
            continue
        depth, i = 0, q - 1
        while i >= 0:
            if mask[i]:
                ch = line[i]
                if ch in ")]}":
                    depth += 1
                elif ch in "([{":
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0:
                    if line.startswith("=>", i):
                        i += 1  # past the arrow
                        break
                    if ch in ",;?:" or (ch == "=" and line[i + 1:i + 2] not in ("=", ">") and line[i - 1:i] not in ("=", "!", "<", ">")) \
                            or re.search(r"(^|\W)return$", line[:i + 1]):
                        break
            elif depth == 0 and line.startswith("${", i - 1):
                break  # the start of a template substitution
            i -= 1
        start = i + 1
        while start < q and line[start] == " ":
            start += 1
        out.append((start, q))
    return out


def js_guards(rel):
    out = []
    for i, l in enumerate(open(os.path.join(ROOT, rel)).read().split("\n")):
        if JS_IF.match(l) and js_cond(l):
            out.append((rel, i + 1, l.strip()))
        elif JS_BOOL.match(l):
            for k in range(len(OP.findall(l))):
                out.append((rel, (i + 1, k), f"{l.strip()} [operator {k + 1} flipped]"))
        for k in range(len(JS_FOR.findall(l))):
            out.append((rel, (i + 1, k, "for"), f"{l.strip()} [loop condition {k + 1} forced false]"))
        if not l.lstrip().startswith("//"):
            for k in range(len(ternaries(l))):
                out.append((rel, (i + 1, k, "?"), f"{l.strip()} [ternary {k + 1} forced to its else]"))
    return out


# Scripts none of whose guards can turn into an endless loop (their loops
# run over finite input): a timeout there is slowness, never a catch. They
# are also the slow ones (OCR, a walk of all history), so they run in a phase
# of their own with fewer workers, to finish rather than starve.
NO_HANGS = {"hack/hygiene.sh"}


SH_IF = re.compile(r"^(\s*(?:el)?if )(.+?)(; then\b.*)$")
# A loop's condition: `while <c>; do` / `until <c>; do`.
SH_LOOP = re.compile(r"^(\s*(while|until) )(.+?)(; do\b.*)$")
SH_ARM = re.compile(r"^(\s*)([^\s#()][^()]*?)\)\s+(.+?)\s*;;\s*$")
# An arm whose body follows on the next lines: `<pat>)` alone on its line.
SH_ARM_OPEN = re.compile(r"^(\s*)([^\s#()][^()]*?)\)\s*(#.*)?$")
NEVER = "__guard_sweep_never_matches__"
# A whole `case ... in <pat>) <body> ;; ... esac` on one line.
SH_CASE_LINE = re.compile(r"^\s*case .* in (.*) esac\s*$")
SH_INLINE_ARM = re.compile(r"(?:^|;;)\s*([^\s()]+)\)\s*((?:(?!;;).)*?)\s*(?=;;)")


def inline_arms(line):
    """(start, end) of the body of each arm with a body, in a one-line case."""
    m = SH_CASE_LINE.match(line)
    if not m:
        return []
    off = m.start(1)
    return [(off + a.start(2), off + a.end(2)) for a in SH_INLINE_ARM.finditer(m.group(1)) if a.group(2).strip()]


def split_list(line):
    """(start, end) of the action after the last top-level `||` or `&&` in a
    shell line, outside quotes, $( ), [ ] and { }: it runs to the next
    top-level `;` or the end of the line. None if there is none."""
    depth, quote, last, end, i = 0, None, None, None, 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            if last is not None and end is None:
                end = i  # the action ends where the comment starts
            break
        elif c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        elif depth == 0 and line[i:i + 2] in ("||", "&&"):
            last, end = i + 2, None
            i += 1
        elif depth == 0 and c == ";" and last is not None and end is None:
            end = i
        i += 1
    if last is None:
        return None
    end = len(line) if end is None else end
    if line[last:end].strip() in ("true", ":", ""):
        return None  # already tolerant: not a guard
    return last, end


def code_lines(lines):
    """Whether each line starts as shell code, not inside a quoted string or
    a heredoc that spans lines (an awk program, a here-document)."""
    code, quote, heredoc = [], None, None
    for l in lines:
        code.append(quote is None and heredoc is None)
        if heredoc is not None:
            if l.strip() == heredoc:
                heredoc = None
            continue
        i = 0
        while i < len(l):
            c = l[i]
            if quote:
                if c == "\\" and quote == '"':
                    i += 1
                elif c == quote:
                    quote = None
            elif c in "'\"":
                quote = c
            elif c == "#" and (i == 0 or l[i - 1] in " \t"):
                break
            elif l.startswith("<<<", i):
                i += 2  # a here-string: one word, not a heredoc
            elif l.startswith("<<", i):
                m = re.match(r"<<-?\s*['\"]?(\w+)['\"]?", l[i:])
                if m:
                    heredoc = m.group(1)
            i += 1
    return code


def shell_guards(rel):
    out, in_case = [], 0
    lines = open(os.path.join(ROOT, rel)).read().split("\n")
    for i, (l, is_code) in enumerate(zip(lines, code_lines(lines))):
        t = l.strip()
        if t.startswith("#") or not t or not is_code:
            continue
        if re.match(r"^case .* in$", t):
            in_case += 1
            continue
        if t == "esac":
            in_case -= 1
            continue
        if inline_arms(l):
            for k in range(len(inline_arms(l))):
                out.append((rel, (i + 1, k), f"{t} [arm {k + 1} emptied]"))
        elif SH_IF.match(l) or SH_LOOP.match(l) or (in_case and (SH_ARM.match(l) or SH_ARM_OPEN.match(l))) or \
                (split_list(l) is not None and not t.startswith(("trap ", "if ", "elif ", "|"))):
            out.append((rel, i + 1, t))
    return out


def mutate_shell(line):
    m = SH_LOOP.match(line)
    if m:  # the loop never runs
        return m.group(1) + ("false" if m.group(2) == "while" else "true") + m.group(4)
    m = SH_ARM_OPEN.match(line)
    if m and not SH_IF.match(line) and split_list(line) is None:
        return f"{m.group(1)}{NEVER})"  # the arm is gone: input falls to the next one
    m = SH_IF.match(line)
    if m:
        return m.group(1) + "false" + m.group(3)
    k = split_list(line)
    if k is not None:
        return line[:k[0]] + " true" + line[k[1]:]
    m = SH_ARM.match(line)
    return f"{m.group(1)}{m.group(2)}) : ;;"


WORKTREE_LOCK = threading.Lock()


def worktree():
    # Parallel `git worktree add`s race on .git/worktrees/: one at a time,
    # each under a name of its own.
    d = tempfile.mkdtemp()
    wt = os.path.join(d, "wt-" + os.path.basename(d))
    with WORKTREE_LOCK:
        subprocess.run(["git", "-C", ROOT, "worktree", "add", "-q", "--detach", wt, "HEAD"], check=True)
    return wt


def mutate(path, n):
    """Disable the guard keyed n in path; return the original lines."""
    lines = open(path).read().split("\n")
    mutated = lines[:]
    if path.endswith(".py"):
        src = "\n".join(lines)
        open(path, "w").write(mutate_py(src, n))
        return lines
    if path.endswith(".yml"):
        n, k, kind = n
        mutated[n - 1] = mutate_wf(lines[n - 1], k, kind)
        open(path, "w").write("\n".join(mutated))
        return lines
    if path.endswith(".go") and isinstance(n, tuple) and n[-1] != "sh":
        line, kind, k = n
        c = next(c for c in gocond([os.path.basename(path)], os.path.dirname(path))
                 if (c["line"], c["kind"], c["k"]) == (line, kind, k))
        with open(path, "rb") as f:
            b = f.read()
        with open(path, "wb") as f:
            f.write(b[:c["start"]] + c["new"].encode() + b[c["end"]:])
        return lines
    if isinstance(n, tuple) and n[-1] == "sh":  # shell inside a Go raw string
        mutated[n[0] - 1] = mutate_shell(lines[n[0] - 1])
        open(path, "w").write("\n".join(mutated))
        return lines
    if path.endswith(".html") and isinstance(n, tuple) and n[-1] == "for":  # a loop that never runs
        line, k, _ = n
        m = list(JS_FOR.finditer(lines[line - 1]))[k]
        mutated[line - 1] = lines[line - 1][:m.start(2)] + " false" + lines[line - 1][m.end(2):]
        open(path, "w").write("\n".join(mutated))
        return lines
    if isinstance(n, tuple) and len(n) == 3:  # a ternary, forced to its else branch
        n, k, _ = n
        a, q = ternaries(lines[n - 1])[k]
        l = lines[n - 1]
        mutated[n - 1] = l[:a] + "(false && (" + l[a:q].rstrip() + ")) " + l[q:]
        open(path, "w").write("\n".join(mutated))
        return lines
    if isinstance(n, tuple) and not path.endswith((".go", ".html")):  # an arm of a one-line case
        n, k = n
        a, b = inline_arms(lines[n - 1])[k]
        mutated[n - 1] = lines[n - 1][:a] + ":" + lines[n - 1][b:]
        open(path, "w").write("\n".join(mutated))
        return lines
    if isinstance(n, tuple):
        n, k = n
        at = [m.start() for m in OP.finditer(lines[n - 1])][k]
        mutated[n - 1] = lines[n - 1][:at] + ("||" if lines[n - 1][at] == "&" else "&&") + lines[n - 1][at + 2:]
        open(path, "w").write("\n".join(mutated))
        return lines
    if path.endswith(".html"):
        a, b = js_cond(lines[n - 1])
        mutated[n - 1] = lines[n - 1][:a] + "false && (" + lines[n - 1][a:b] + ")" + lines[n - 1][b:]
        open(path, "w").write("\n".join(mutated))
        return lines
    mutated[n - 1] = mutate_shell(lines[n - 1])
    open(path, "w").write("\n".join(mutated))
    return lines


def guards():
    files = []
    for d in GO_DIRS:
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            files += [os.path.relpath(os.path.join(dp, f), ROOT) for f in sorted(fs)
                      if f.endswith(".go") and not f.endswith("_test.go")]
    out, lines = [], {}
    for c in gocond(sorted(files), ROOT):
        if c["file"] not in lines:
            lines[c["file"]] = open(os.path.join(ROOT, c["file"])).read().split("\n")
        text = go_text(lines[c["file"]][c["line"] - 1].strip(), c["kind"], c["k"])
        out.append((c["file"], (c["line"], c["kind"], c["k"]), text))
    return out


# Headroom. Every mutant is a fresh build, so a sweep writes gigabytes of Go
# build cache; unchecked, sweeps filled a laptop's disk twice. The sweep
# refuses to start without MIN_FREE free where it writes, builds into a cache
# of its own (not the user's), empties that cache when it passes MAX_CACHE or
# free space dips under MIN_FREE, stops if emptying it does not restore the
# headroom, and removes it at the end.
GIB = 1 << 30
MIN_FREE = float(os.environ.get("GUARD_SWEEP_MIN_FREE_GB", "5")) * GIB
MAX_CACHE = float(os.environ.get("GUARD_SWEEP_MAX_CACHE_GB", "4")) * GIB
CACHE_CHECK_EVERY = 30  # seconds between measurements of the cache's size


class NoHeadroom(Exception):
    pass


def free_bytes(path):
    return shutil.disk_usage(path).free


def short_of_space(paths):
    """The first of paths whose filesystem has less than MIN_FREE free, with
    its free bytes; (None, 0) if none is short."""
    for p in paths:
        free = free_bytes(p)
        if free < MIN_FREE:
            return p, free
    return None, 0


def dir_size(path):
    total = 0
    for dp, _, fs in os.walk(path):
        for f in fs:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


class Cache:
    """The sweep's own Go build cache. Commands run under a shared hold; it is
    emptied only while none runs, so no build ever loses files mid-way."""

    def __init__(self, path):
        self.path, self.running, self.checked = path, 0, 0.0
        self.cond = threading.Condition()

    def hold(self):
        with self.cond:
            self.running += 1

    def release(self):
        with self.cond:
            self.running -= 1
            self.cond.notify_all()

    def keep_in_bounds(self, force=False):
        """Empty the cache if it has grown past MAX_CACHE (measured at most
        every CACHE_CHECK_EVERY seconds) or free space is under MIN_FREE;
        raise NoHeadroom if space is still short after emptying it."""
        if not force and free_bytes(self.path) >= MIN_FREE and time.time() - self.checked < CACHE_CHECK_EVERY:
            return
        with self.cond:
            self.checked = time.time()
            if free_bytes(self.path) >= MIN_FREE and dir_size(self.path) <= MAX_CACHE:
                return
            while self.running:
                self.cond.wait()
            shutil.rmtree(self.path, ignore_errors=True)
            os.makedirs(self.path, exist_ok=True)
            free = free_bytes(self.path)
            if free < MIN_FREE:
                raise NoHeadroom(f"only {free / GIB:.1f} GiB free on {self.path}'s filesystem even with the sweep's build cache emptied; need {MIN_FREE / GIB:.1f}")


CACHE = None  # set by main(): the sweep's own build cache


def run(items, cmd, env=None):
    wt = worktree()
    res = []
    try:
        for f, n, text in items:
            path = os.path.join(wt, f)
            if CACHE:
                CACHE.keep_in_bounds()
                CACHE.hold()
            orig = mutate(path, n)
            # Own session: a mutant that never ends (an argument loop without
            # its shift) is killed with everything it started, not orphaned.
            try:
                p = subprocess.Popen(cmd(f), cwd=wt, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=env and env(wt), start_new_session=True)
                out, err = p.communicate()
            finally:
                if CACHE:
                    CACHE.release()
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            r = subprocess.CompletedProcess(p.args, p.returncode, out, err)
            open(path, "w").write("\n".join(orig))
            # GUARD_SWEEP_LOG=DIR keeps each mutant's output, so a surprising
            # verdict (an accepted entry gone stale) can be read, not guessed.
            if os.environ.get("GUARD_SWEEP_LOG"):
                os.makedirs(os.environ["GUARD_SWEEP_LOG"], exist_ok=True)
                name = re.sub(r"[^\w.-]+", "_", f"{f}:{n}")[:200]
                with open(os.path.join(os.environ["GUARD_SWEEP_LOG"], name + ".log"), "w") as log:
                    log.write(f"{text}\nexit {r.returncode}\n{out}\n{err}")
            survived = r.returncode == 0
            if not survived and ("[build failed]" in r.stdout or "[setup failed]" in r.stdout):
                print(f"does not compile (the build notices): {f}:{n}", file=sys.stderr)
            # A timeout counts as noticed where a mutant can hang (an argument
            # loop without its shift). Where none can (NO_HANGS), it only
            # means slow: count it as not noticed, so it fails --check out
            # loud instead of passing as a catch.
            if "panic: test timed out" in r.stdout:
                hang = f not in NO_HANGS
                print(f"timed out ({'a hang: noticed' if hang else 'slow, cannot hang: NOT counted as noticed'}): {f}:{n}", file=sys.stderr)
                survived = survived or not hang
            # A browser check that fails without saying FAIL broke, it did not
            # judge: count that as no test noticing, never as a catch.
            if not survived and cmd(f) == ["./hack/check-ui.sh"] and "\nFAIL " not in "\n" + r.stdout:
                print(f"no verdict (the browser check broke) for {f}:{n}", file=sys.stderr)
                survived = True
            res.append((survived, f, n, text))
    finally:
        subprocess.run(["git", "-C", ROOT, "worktree", "remove", "--force", wt])
    return res


def parallel(items, cmd, workers=6):
    chunks = [items[i::workers] for i in range(workers)]
    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        return [r for rs in ex.map(lambda c: run(c, cmd), chunks) for r in rs]


def main():
    short, free = short_of_space([tempfile.gettempdir(), ROOT])
    if short:
        print(f"guard-sweep: refusing to start: {free / GIB:.1f} GiB free on {short}'s filesystem, and a sweep writes "
              f"gigabytes of worktrees and build cache; need {MIN_FREE / GIB:.1f} (GUARD_SWEEP_MIN_FREE_GB)", file=sys.stderr)
        sys.exit(3)
    # Guards are found in the working tree but mutated in a worktree of HEAD:
    # with uncommitted changes the two differ, and a mutant would land on
    # the wrong line, or none.
    dirty = subprocess.run(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout
    if dirty.strip():
        print("guard-sweep: commit first: the sweep mutates HEAD, and the working tree differs:\n" + dirty, file=sys.stderr)
        sys.exit(2)
    global CACHE
    CACHE = Cache(tempfile.mkdtemp(prefix="guard-sweep-gocache-"))
    previous = os.environ.get("GOCACHE")
    os.environ["GOCACHE"] = CACHE.path  # every go command the sweep starts builds here
    try:
        sweep()
    except NoHeadroom as e:
        print(f"guard-sweep: stopped: {e}", file=sys.stderr)
        sys.exit(3)
    finally:
        shutil.rmtree(CACHE.path, ignore_errors=True)
        CACHE = None
        if previous is None:
            os.environ.pop("GOCACHE", None)
        else:
            os.environ["GOCACHE"] = previous


def sweep():
    if len(sys.argv) == 3 and sys.argv[1] == "--e2e":
        items = []
        for l in open(sys.argv[2]):
            loc, text = l.split(": ", 1)
            f, n = loc.rsplit(":", 1)
            items.append((f, int(n), text.strip()))
        kc = os.path.join(ROOT, ".e2e", "kubeconfig")
        cmd = lambda f: ["go", "test", "-tags", "e2e", "-count=1", "-timeout", "15m", "-run", "^TestE2E$", "./test/e2e/"]
        env = lambda wt: dict(os.environ, PODPEERS_E2E_KUBECONFIG=kc, PODPEERS_E2E_OUT=os.path.join(wt, ".e2e-out"))
        for survived, f, n, text in run(items, cmd, env):  # one cluster: one at a time
            print(f"{'cluster-SURVIVED' if survived else 'cluster-killed'} {f}:{n}: {text}", flush=True)
        return
    only = "--browser-only" in sys.argv
    browser = only or "--browser" in sys.argv
    # CI splits the rest in two jobs that run side by side.
    go_only, scripts_only = "--go-only" in sys.argv, "--scripts-only" in sys.argv
    no_go, no_scripts = only or scripts_only, only or go_only
    cmd = lambda f: SHELL_TESTS.get(f) or WF_TESTS.get(f) or PY_TESTS.get(f) or EMBEDDED_SH.get(f) or JS_TESTS[f]
    if browser:
        # The browser checks must pass unmutated first: in a broken
        # environment every mutant would fail them, for the wrong reason.
        wt = worktree()
        try:
            for c in sorted({tuple(v) for k, v in SHELL_TESTS.items() if k.startswith("hack/check-")} | {tuple(v) for v in JS_TESTS.values()}):
                r = subprocess.run(list(c), cwd=wt, capture_output=True, text=True)
                if r.returncode != 0:
                    print(f"baseline: {' '.join(c)} fails unmutated; nothing swept\n{r.stdout[-2000:]}{r.stderr[-2000:]}", file=sys.stderr)
                    sys.exit(1)
        finally:
            subprocess.run(["git", "-C", ROOT, "worktree", "remove", "--force", wt])
    own = [] if no_go else parallel(guards(), lambda f: ["go", "test", "-count=1", "./" + os.path.dirname(f) + "/"])
    first = [(f, n, t) for survived, f, n, t in own if survived]
    whole = parallel(first, lambda f: ["go", "test", "-count=1", "./internal/...", "./cmd/...", "./test/skillscript/", "./hack/gocond/"])
    left = [(f, n, t) for survived, f, n, t in whole if survived]
    sh = [] if no_scripts else [g for rel in SHELL_TESTS if not rel.startswith("hack/check-") for g in shell_guards(rel)]
    sh += [] if no_scripts else [g for rel in WF_TESTS for g in wf_guards(rel)]
    sh += [] if no_scripts else [g for rel in PY_TESTS for g in py_guards(rel)]
    sh += [] if no_scripts else [g for rel in EMBEDDED_SH for g in embedded_guards(rel)]
    # The browser check uses one port and one Chrome: its guards run one at a time.
    browser = browser and not (go_only or scripts_only)
    br = [g for rel in SHELL_TESTS if browser and rel.startswith("hack/check-") for g in shell_guards(rel)]
    br += [g for rel in JS_TESTS if browser for g in js_guards(rel)]
    slow = [g for g in sh if g[0] in NO_HANGS]
    shres = parallel([g for g in sh if g[0] not in NO_HANGS], cmd) + parallel(slow, cmd, workers=2) + \
        (parallel(br, cmd, workers=1) if br else [])
    sh += br
    left = sorted(left + [(f, n, t) for survived, f, n, t in shres if survived], key=lambda x: (x[0], str(x[1]), x[2]))
    for f, n, t in left:
        print(f"{f}:{n[0] if isinstance(n, tuple) else n}: {t}")
    print(f"{len(own)} Go guards, {len(sh) - len(br)} shell, Make, workflow and Python guards, {len(br)} browser-checked guards; {len(left)} survive their tests", file=sys.stderr)
    if "--check" in sys.argv:
        sys.exit(check(left, browser, only, go=not no_go, scripts=not no_scripts))


def check(left, browser, only=False, go=None, scripts=None):
    """Every survivor must be accepted with a reason, and every acceptance
    must still be a survivor. Only the entries for what was swept are
    checked: the browser-checked ones with --browser; the Go ones unless
    --browser-only or --scripts-only; the rest unless --browser-only or
    --go-only."""
    go = not only if go is None else go
    scripts = not only if scripts is None else scripts
    accepted = []
    for line in open(os.path.join(ROOT, "hack", "guard-sweep-accepted.txt")):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # file | guard | category | reason: a guard may itself hold " | " (a
        # shell pipe), so the file is the first field and the category and
        # reason the last two.
        f, rest = line.split(" | ", 1)
        text, category, reason = [x.strip() for x in rest.rsplit(" | ", 2)]
        f = f.strip()
        in_browser = f.startswith("hack/check-") or f in JS_TESTS
        in_go = f.endswith(".go") and not text.endswith("[embedded shell]")
        if (in_browser and browser) or (in_go and go) or (not in_browser and not in_go and scripts):
            accepted.append((f, text))
    pending = accepted[:]
    unaccounted = []
    for f, n, t in left:
        if (f, t) in pending:
            pending.remove((f, t))
        else:
            unaccounted.append(f"{f}:{n[0] if isinstance(n, tuple) else n}: {t}")
    for u in unaccounted:
        print(f"UNACCOUNTED  {u}  (no test notices this guard's removal: add one, or accept it with a reason)", file=sys.stderr)
    for f, t in pending:
        print(f"STALE        {f}: {t}  (accepted, but a test now notices it: remove the entry)", file=sys.stderr)
    return 1 if unaccounted or pending else 0


if __name__ == "__main__":
    main()
