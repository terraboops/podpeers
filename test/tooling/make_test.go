package tooling

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// makeIn runs the repo's Makefile in a scratch module: the recipes are the
// real ones, the code they check is invented, and hack/ holds stubs, so no
// target here can reach a cluster or the real tree.
func makeIn(t *testing.T, files map[string]string, env []string, target string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]string{
		"Makefile":            string(mk),
		"go.mod":              "module example.test/v\n\ngo 1.22\n",
		"a.go":                "package v\n\n// A is fine.\nfunc A() int { return 1 }\n",
		"test/e2e/e.go":       "//go:build e2e\n\npackage e2e\n",
		"hack/hygiene.sh":     "#!/bin/sh\nexit 0\n",
		"hack/e2e-cluster.sh": "#!/bin/sh\nexit 0\n", // never a real cluster
	}
	for k, v := range files {
		all[k] = v
	}
	for p, body := range all {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(body), 0o755)
	}
	c := exec.Command("make", "-s", target)
	c.Dir = dir
	c.Env = append(os.Environ(), append([]string{"GOWORK=off", "GOFLAGS=-mod=mod"}, env...)...)
	out, _ := c.CombinedOutput()
	return c.ProcessState.ExitCode(), string(out)
}

// make vet (which CI runs) fails on unformatted code, and vets the e2e
// suite's build-tagged code as well as the rest.
func TestMakeVetFailsWhatItChecks(t *testing.T) {
	if code, out := makeIn(t, nil, nil, "vet"); code != 0 {
		t.Fatalf("control: clean code should pass make vet: exit %d\n%s", code, out)
	}
	if code, out := makeIn(t, map[string]string{"a.go": "package v\nfunc A() int {return 1}\n"}, nil, "vet"); code == 0 || !strings.Contains(out, "gofmt needed") {
		t.Errorf("unformatted code: exit %d, want a failure naming gofmt\n%s", code, out)
	}
	bad := "//go:build e2e\n\npackage e2e\n\nimport \"fmt\"\n\n// F is wrong only under the e2e tag.\nfunc F() { fmt.Printf(\"%d\\n\", \"x\") }\n"
	if code, out := makeIn(t, map[string]string{"test/e2e/e.go": bad}, nil, "vet"); code == 0 {
		t.Errorf("a vet error in e2e-tagged code: exit 0, want a failure\n%s", out)
	}
}

// make e2e says which tool it lacks before it runs anything. The tools are
// hidden by a PATH that links every other command.
func TestMakeE2ENamesAMissingTool(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bin")
	os.MkdirAll(bin, 0o755)
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if e.Name() != "helm" && e.Name() != "kwokctl" {
				os.Symlink(filepath.Join(d, e.Name()), filepath.Join(bin, e.Name()))
			}
		}
	}
	if code, out := makeIn(t, nil, []string{"PATH=" + bin}, "e2e"); code == 0 || !strings.Contains(out, "e2e needs helm") {
		t.Errorf("without helm: exit %d, want it named\n%s", code, out)
	}
	os.WriteFile(filepath.Join(bin, "helm"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if code, out := makeIn(t, nil, []string{"PATH=" + bin}, "e2e"); code == 0 || !strings.Contains(out, "e2e needs kwokctl") {
		t.Errorf("without kwokctl: exit %d, want it named\n%s", code, out)
	}
}

// The workflow cannot run here; what can be observed is what it declares.
// Each gate below must stay a step of its job, with the flags that make a
// missing tool fail it rather than skip it, on every push to main and every
// pull request, with nothing that lets it fail quietly.
func TestWorkflowDeclaresEveryGate(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		// YAML 1.1 reads the key `on` as the boolean true.
		On struct {
			Push struct {
				Branches []string `json:"branches"`
			} `json:"push"`
		} `json:"true"`
		Jobs map[string]struct {
			ContinueOnError any `json:"continue-on-error"`
			Steps           []struct {
				Run             string            `json:"run"`
				With            map[string]any    `json:"with"`
				Uses            string            `json:"uses"`
				ContinueOnError any               `json:"continue-on-error"`
				Env             map[string]string `json:"env"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if len(wf.On.Push.Branches) != 1 || wf.On.Push.Branches[0] != "main" || !regexp.MustCompile(`(?m)^  pull_request:`).Match(raw) {
		t.Errorf("CI must run on every push to main and every pull request: %+v", wf.On)
	}
	gates := map[string][]string{
		"unit": {
			`^HYGIENE_IMAGES=1 ./hack/hygiene.sh$`,
			`^HYGIENE_IMAGES=1 ./hack/hygiene.sh --history$`,
			`^make vet$`,
			`^PODPEERS_REQUIRE_DOT=1 PODPEERS_REQUIRE_OCR=1 go test -race -count=1 ./...$`,
			`^PODPEERS_REQUIRE_OCR=1 ./hack/mutants.sh --ui$`,
			`^bash -n hack/e2e-cluster.sh skills/podpeers-netpol/scripts/netpol-check.sh$`,
			`^make build$`,
			`^python3 hack/guard_sweep_test.py$`,
		},
		"guards-go":      {`^GUARD_SWEEP_LOG=\S+ python3 hack/guard-sweep.py --check --go-only$`},
		"guards-scripts": {`^PODPEERS_REQUIRE_OCR=1 GUARD_SWEEP_LOG=\S+ python3 hack/guard-sweep.py --check --scripts-only$`},
		"guards-browser": {`^python3 hack/guard-sweep.py --check --browser-only$`},
		"docs":           {`^./hack/check-docs.sh$`, `^./hack/check-ui.sh$`},
		"e2e":            {`^make e2e$`, `^PODPEERS_REQUIRE_OCR=1 ./hack/mutants.sh --e2e$`, `^GUARD_SWEEP_LOG=\S+ python3 hack/guard-sweep.py --cluster$`},
	}
	// A shallow clone would let the history checks see less and pass.
	fullHistory := map[string]bool{"unit": true, "guards-scripts": true, "e2e": true}
	for job, want := range gates {
		j, ok := wf.Jobs[job]
		if !ok {
			t.Errorf("job %s is gone", job)
			continue
		}
		if j.ContinueOnError != nil {
			t.Errorf("job %s may fail quietly (continue-on-error)", job)
		}
		for _, w := range want {
			found := false
			for _, s := range j.Steps {
				if regexp.MustCompile(w).MatchString(strings.TrimSpace(s.Run)) {
					found = true
				}
			}
			if !found {
				t.Errorf("job %s no longer runs %s", job, w)
			}
		}
		full := false
		for _, s := range j.Steps {
			if s.ContinueOnError != nil {
				t.Errorf("job %s: step %q may fail quietly (continue-on-error)", job, s.Run)
			}
			if strings.Contains(s.Run, "|| true") && !strings.Contains(s.Run, "e2e-cluster.sh down") {
				t.Errorf("job %s: step %q swallows its own failure", job, s.Run)
			}
			if strings.HasPrefix(s.Uses, "actions/checkout") && s.With["fetch-depth"] == float64(0) {
				full = true
			}
		}
		if fullHistory[job] && !full {
			t.Errorf("job %s must check out the full history", job)
		}
	}
}
