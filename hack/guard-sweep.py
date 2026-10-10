#!/usr/bin/env python3
"""Remove every guard, one at a time, and see whether any test notices.

A guard here is any `if <condition> {` in non-test Go code under internal/ and
cmd/. Each is rewritten to `if false && (<condition>) {` in a scratch worktree
of HEAD, and the unit tests run: first only that package's (fast), then, for
the survivors, the whole unit suite (a guard may be tested from another
package). What survives both is a guard whose removal no unit test notices.
Each survivor is then accounted for in docs/guard-sweep.md: tested on the real
cluster (hack/guard-sweep.py --e2e measures it), or why it is not a finding.

  hack/guard-sweep.py              unit sweep; prints survivors
  hack/guard-sweep.py --check      unit sweep, compared with
                                   hack/guard-sweep-accepted.txt: fails on a
                                   survivor nobody has accounted for, and on an
                                   accepted entry that no longer survives
  hack/guard-sweep.py --e2e FILE   for each survivor listed in FILE (lines as
                                   printed by the unit sweep), run the real-
                                   cluster TestE2E instead (needs make e2e-cluster)

Accepted entries are matched by file and guard text, not line number, so
edits elsewhere in a file do not invalidate them.
"""
import concurrent.futures
import os
import re
import subprocess
import sys
import tempfile

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
IF = re.compile(r"^(\s*)(\} else )?if (.+) \{\s*$")


def worktree():
    wt = tempfile.mkdtemp() + "/wt"
    subprocess.run(["git", "-C", ROOT, "worktree", "add", "-q", "--detach", wt, "HEAD"], check=True)
    return wt


def mutate(path, n):
    """Disable the guard on line n of path; return the original lines."""
    lines = open(path).read().split("\n")
    m = IF.match(lines[n - 1])
    cond = m.group(3)
    if ";" in cond:
        init, c = cond.rsplit(";", 1)
        new = f"{m.group(1)}{m.group(2) or ''}if {init}; false && ({c.strip()}) {{"
    else:
        new = f"{m.group(1)}{m.group(2) or ''}if false && ({cond}) {{"
    mutated = lines[:]
    mutated[n - 1] = new
    open(path, "w").write("\n".join(mutated))
    return lines


def guards():
    out = []
    for dp, _, fs in os.walk(ROOT):
        rel = os.path.relpath(dp, ROOT)
        if not (rel.startswith("internal") or rel.startswith("cmd")):
            continue
        for f in sorted(fs):
            if f.endswith(".go") and not f.endswith("_test.go"):
                for i, l in enumerate(open(os.path.join(dp, f)).read().split("\n")):
                    if IF.match(l):
                        out.append((os.path.join(rel, f), i + 1, l.strip()))
    return out


def run(items, cmd, env=None):
    wt = worktree()
    res = []
    try:
        for f, n, text in items:
            path = os.path.join(wt, f)
            orig = mutate(path, n)
            r = subprocess.run(cmd(f), cwd=wt, capture_output=True, text=True, env=env and env(wt))
            open(path, "w").write("\n".join(orig))
            res.append((r.returncode == 0, f, n, text))
    finally:
        subprocess.run(["git", "-C", ROOT, "worktree", "remove", "--force", wt])
    return res


def parallel(items, cmd, workers=6):
    chunks = [items[i::workers] for i in range(workers)]
    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        return [r for rs in ex.map(lambda c: run(c, cmd), chunks) for r in rs]


def main():
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
    own = parallel(guards(), lambda f: ["go", "test", "-count=1", "./" + os.path.dirname(f) + "/"])
    first = [(f, n, t) for survived, f, n, t in own if survived]
    whole = parallel(first, lambda f: ["go", "test", "-count=1", "./internal/...", "./cmd/...", "./test/skillscript/"])
    left = sorted((f, n, t) for survived, f, n, t in whole if survived)
    for f, n, t in left:
        print(f"{f}:{n}: {t}")
    print(f"{len(own)} guards, {len(left)} survive the whole unit suite", file=sys.stderr)
    if sys.argv[1:] == ["--check"]:
        sys.exit(check(left))


def check(left):
    """Every survivor must be accepted with a reason, and every acceptance
    must still be a survivor."""
    accepted = []
    for line in open(os.path.join(ROOT, "hack", "guard-sweep-accepted.txt")):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f, text, category, reason = [x.strip() for x in line.split(" | ", 3)]
        accepted.append((f, text))
    pending = accepted[:]
    unaccounted = []
    for f, n, t in left:
        if (f, t) in pending:
            pending.remove((f, t))
        else:
            unaccounted.append(f"{f}:{n}: {t}")
    for u in unaccounted:
        print(f"UNACCOUNTED  {u}  (no test notices this guard's removal: add one, or accept it with a reason)", file=sys.stderr)
    for f, t in pending:
        print(f"STALE        {f}: {t}  (accepted, but a test now notices it: remove the entry)", file=sys.stderr)
    return 1 if unaccounted or pending else 0


if __name__ == "__main__":
    main()
