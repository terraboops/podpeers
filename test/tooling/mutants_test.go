package tooling

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The mutant harness's verdict is what every "all mutants killed" claim in
// this repo rests on. These run hack/mutants.sh in a tiny scratch repo whose
// "protection" is one function, with mutants of known outcome, a fake e2e
// test and a fake browser check (FAKE_*_BROKEN breaks each baseline), and
// require it to name each outcome right and pass or fail the run with it.

type harness struct {
	t         *testing.T
	root, bin string
}

const header = "# Mutant: breaks the protection for \"x\".\n# unit-pkg: ./internal/a/\n"

func newHarness(t *testing.T) *harness {
	root, _ := copyScript(t, "mutants.sh")
	bin, _ := shims(t, root) // kubectl answers $FAKE_CTX for the --e2e context check
	h := &harness{t: t, root: root, bin: bin}
	broken := func(v string) string {
		return "\tif os.Getenv(\"" + v + "\") != \"\" {\n\t\tt.Fatal(\"baseline broken\")\n\t}\n"
	}
	for p, body := range map[string]string{
		"go.mod":          "module example.test/m\n\ngo 1.22\n",
		"internal/a/a.go": "package a\n\n// Ok is the protection.\nfunc Ok() bool { return true }\n\n// Spare is untested.\nfunc Spare() int { return 1 }\n",
		"internal/a/b.go": "package a\n\n// B is a file the code base moves on from.\nconst B = 1\n",
		"internal/a/a_test.go": "package a\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestOk(t *testing.T) {\n" + broken("FAKE_UNIT_BROKEN") +
			"\tif !Ok() {\n\t\tt.Fatal(\"protection gone\")\n\t}\n}\n\nfunc TestNot(t *testing.T) {\n\tif Spare() > 5 {\n\t\tt.Fatal(\"spare too big\")\n\t}\n}\n",
		"cmd/c/main.go":              "package main\n\nfunc main() {}\n",
		"test/skillscript/s_test.go": "package skillscript\n",
		"test/hygiene/h_test.go":     "package hygiene\n",
		"test/e2e/e_test.go": "//go:build e2e\n\npackage e2e\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"example.test/m/internal/a\"\n)\n\nfunc TestE2E(t *testing.T) {\n" +
			broken("FAKE_E2E_BROKEN") + "\tif !a.Ok() {\n\t\tt.Fatal(\"protection gone on the cluster\")\n\t}\n}\n",
		"hack/check-ui.sh": "#!/bin/sh\n[ -n \"$FAKE_UI_BROKEN\" ] && { echo baseline broken; exit 1; }\ngo test -count=1 -run TestOk ./internal/a/ && exit 0\necho \"protection gone in the browser\"; exit 1\n",
	} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o755)
	}
	os.MkdirAll(filepath.Join(root, "hack", "mutants"), 0o755)
	h.git("init", "-q")
	h.commit()
	return h
}

func (h *harness) git(args ...string) {
	h.t.Helper()
	// No background maintenance: it could outlive the test in .git.
	c := exec.Command("git", append([]string{"-c", "gc.auto=0", "-c", "maintenance.auto=false"}, args...)...)
	c.Dir = h.root
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	if out, err := c.CombinedOutput(); err != nil {
		h.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func (h *harness) commit() { h.git("add", "-A"); h.git("commit", "-qm", "change") }

// mutant writes hack/mutants/NAME.patch: a real git diff of one edit, under
// the given header fields.
func (h *harness) mutant(name, file, from, to, fields string) {
	h.t.Helper()
	p := filepath.Join(h.root, file)
	before, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(before), from, to, 1)), 0o644)
	c := exec.Command("git", "diff")
	c.Dir = h.root
	diff, err := c.Output()
	if err != nil || len(diff) == 0 {
		h.t.Fatalf("diff for %s: %v", name, err)
	}
	os.WriteFile(filepath.Join(h.root, "hack", "mutants", name+".patch"), append([]byte(header+fields), diff...), 0o644)
	os.WriteFile(p, before, 0o644)
}

func (h *harness) run(env []string, args ...string) (int, string) {
	h.t.Helper()
	return run(h.t, append([]string{"GOFLAGS=-mod=mod", "GOWORK=off", "PATH=" + h.bin + ":" + os.Getenv("PATH"), "FAKE_CTX=k3d-podpeers-e2e"}, env...),
		"bash", append([]string{filepath.Join(h.root, "hack", "mutants.sh")}, args...)...)
}

const (
	unitOnly    = "# unit-run: .\n# unit-expect: protection gone\n# e2e-run: -\n"
	everywhere  = "# unit-run: .\n# unit-expect: protection gone\n# e2e-run: TestE2E\n# e2e-expect: protection gone on the cluster\n# ui-expect: protection gone in the browser\n"
	clusterOnly = "# unit-run: -\n# e2e-run: TestE2E\n# e2e-expect: protection gone on the cluster\n"
)

func TestMutantHarnessJudgesEachMutantRight(t *testing.T) {
	h := newHarness(t)
	a := "internal/a/a.go"
	h.mutant("01-killed", a, "return true", "return false", unitOnly)                                     // TestOk fails as claimed
	h.mutant("02-survives", a, "return 1", "return 2", "# unit-run: .\n# unit-expect: x\n# e2e-run: -\n") // nothing reads it
	h.mutant("03-wrong-reason", a, "return 1", "return 9", unitOnly)                                      // fails, but not as claimed
	h.mutant("04-stale", "internal/a/b.go", "const B = 1", "const B = 2", unitOnly)                       // made stale below
	h.mutant("05-no-compile", a, "return true", "return nope", unitOnly)
	h.mutant("06-cluster-only", a, "return true", "return false", clusterOnly)
	os.WriteFile(filepath.Join(h.root, "internal/a/b.go"), []byte("package a\n\n// B is a file the code base moves on from.\nconst B = 3\n"), 0o644)
	h.commit()

	code, out := h.run(nil)
	for _, want := range []string{
		"01-killed                unit: killed     e2e: n/a        ui: n/a",
		"02-survives              unit: SURVIVED",
		"03-wrong-reason          unit: UNEXPECTED",
		"04-stale: patch no longer applies",
		"05-no-compile: mutant does not compile",
		"06-cluster-only          unit: n/a        e2e: skipped",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in the harness output", want)
		}
	}
	if code != 1 || strings.Contains(out, "all mutants killed") {
		t.Errorf("a surviving, misfiring, stale or broken mutant must fail the run: exit %d", code)
	}
	if t.Failed() {
		t.Fatalf("output:\n%s", out)
	}
	// A survivor alone, or a mutant killed for the wrong reason alone, must
	// fail the run: nothing else (a stale or broken patch) may be what fails it.
	for _, keep := range []string{"02-survives", "03-wrong-reason"} {
		for _, name := range []string{"02-survives", "03-wrong-reason", "04-stale", "05-no-compile"} {
			if name != keep {
				os.Remove(filepath.Join(h.root, "hack", "mutants", name+".patch"))
			}
		}
		h.commit()
		if code, out := h.run(nil); code != 1 || strings.Contains(out, "all mutants killed") {
			t.Fatalf("with %s the only bad mutant: exit %d, want 1\n%s", keep, code, out)
		}
		h.git("checkout", "-q", "HEAD~1", "--", "hack/mutants")
		h.commit()
	}
	// Control: with only the good mutants, the run passes.
	for _, name := range []string{"02-survives", "03-wrong-reason", "04-stale", "05-no-compile"} {
		os.Remove(filepath.Join(h.root, "hack", "mutants", name+".patch"))
	}
	h.commit()
	if code, out := h.run(nil); code != 0 || !strings.Contains(out, "all mutants killed, each for the expected reason") {
		t.Fatalf("control: exit %d\n%s", code, out)
	}
}

// --e2e and --ui run the mutant on the (fake) cluster and in the (fake)
// browser too; a name filter selects the mutants to run.
func TestMutantHarnessRunsEverySuite(t *testing.T) {
	h := newHarness(t)
	h.mutant("01-everywhere", "internal/a/a.go", "return true", "return false", everywhere)
	h.mutant("02-other", "internal/a/a.go", "return true", "return false", unitOnly)
	h.commit()
	code, out := h.run(nil, "--e2e", "--ui", "everywhere")
	if code != 0 || !strings.Contains(out, "01-everywhere            unit: killed     e2e: killed     ui: killed") || strings.Contains(out, "02-other") {
		t.Fatalf("--e2e --ui everywhere: exit %d\n%s", code, out)
	}
	code, out = h.run(nil)
	if code != 0 || !strings.Contains(out, "01-everywhere            unit: killed     e2e: skipped    ui: skipped") {
		t.Fatalf("without --e2e --ui: exit %d\n%s", code, out)
	}
}

// A broken baseline would make every mutant look killed: each suite's
// baseline must pass first, and the e2e baseline is the e2e tests the
// selected mutants rely on.
func TestMutantHarnessRequiresAPassingBaseline(t *testing.T) {
	h := newHarness(t)
	h.mutant("01-everywhere", "internal/a/a.go", "return true", "return false", everywhere)
	h.commit()
	for _, c := range []struct {
		env, want string
		args      []string
	}{
		{"FAKE_UNIT_BROKEN=1", "baseline unit tests FAIL", nil},
		{"FAKE_UI_BROKEN=1", "baseline browser checks FAIL", []string{"--ui"}},
		{"FAKE_E2E_BROKEN=1", "baseline e2e FAILS", []string{"--e2e"}},
	} {
		if code, out := h.run([]string{c.env}, c.args...); code != 1 || !strings.Contains(out, c.want) || strings.Contains(out, "01-everywhere ") {
			t.Errorf("%s %v: exit %d, want 1 with %q before any mutant\n%s", c.env, c.args, code, c.want, out)
		}
	}
}
