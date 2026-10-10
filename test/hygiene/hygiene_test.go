// Package hygiene tests the public-repo hygiene gate (hack/hygiene.sh): that
// it fires on a planted leak, in the tree, in an image, and in history, and
// lets the clean case and the listed known blob through. A gate nobody has
// seen fire proves nothing. The leaks are built at runtime: written out in
// this file, they would trip the gate on this repository.
package hygiene

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// leakIP is an address outside the documentation and loopback ranges.
var leakIP = fmt.Sprintf("%d.%d.%d.%d", 10, 23, 45, 67)

// repo makes a throwaway git repository holding a copy of the gate and the
// given files, committed one commit per map, in order.
func repo(t *testing.T, commits ...map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		c := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	gate, err := os.ReadFile("../../hack/hygiene.sh")
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "hack"), 0o755)
	os.WriteFile(filepath.Join(dir, "hack", "hygiene.sh"), gate, 0o755)
	git("add", "-A")
	git("commit", "-qm", "gate")
	for _, files := range commits {
		for p, body := range files {
			full := filepath.Join(dir, p)
			if body == "" {
				os.Remove(full)
				continue
			}
			os.MkdirAll(filepath.Dir(full), 0o755)
			os.WriteFile(full, []byte(body), 0o644)
		}
		git("add", "-A")
		git("commit", "-qm", "change")
	}
	return dir
}

func gate(t *testing.T, dir string, args ...string) (int, string) {
	t.Helper()
	c := exec.Command("./hack/hygiene.sh", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "HYGIENE_IMAGES=")
	out, err := c.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestCleanRepoPasses(t *testing.T) {
	dir := repo(t, map[string]string{"README.md": "see 192.0.2.10 and 127.0.0.1\n"})
	for _, args := range [][]string{nil, {"--history"}} {
		if code, out := gate(t, dir, args...); code != 0 {
			t.Fatalf("hygiene.sh %v on a clean repo: exit %d\n%s", args, code, out)
		}
	}
}

func TestTreeLeaksFail(t *testing.T) {
	for name, body := range map[string]string{
		"address":    "connect to " + leakIP + "\n",
		"credential": "users:\n- user:\n    client-key" + "-data: " + strings.Repeat("Q", 40) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := repo(t, map[string]string{"notes.md": body})
			if code, out := gate(t, dir); code == 0 || !strings.Contains(out, "notes.md") {
				t.Fatalf("hygiene.sh let a leaked %s through (exit %d):\n%s", name, code, out)
			}
		})
	}
}

// A leak deleted from the tree is still public: the history mode finds it.
func TestDeletedLeakIsFoundInHistory(t *testing.T) {
	dir := repo(t, map[string]string{"notes.md": "connect to " + leakIP + "\n"}, map[string]string{"notes.md": ""})
	if code, out := gate(t, dir); code != 0 {
		t.Fatalf("the tree is clean now, so the tree check should pass: exit %d\n%s", code, out)
	}
	if code, out := gate(t, dir, "--history"); code == 0 || !strings.Contains(out, leakIP) {
		t.Fatalf("hygiene.sh --history missed a leak deleted from the tree (exit %d):\n%s", code, out)
	}
}

// Text rendered in an image is invisible to grep. The fixture is the real
// early demo frame from this repository's history that shows a throwaway
// cluster's pod address; the history check must find it unless listed.
func TestAddressRenderedInAnImageIsFound(t *testing.T) {
	for _, tool := range []string{"tesseract", "ffmpeg"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("PODPEERS_REQUIRE_OCR") != "" {
				t.Fatalf("%s is required here but not installed", tool)
			}
			t.Skipf("%s is not installed, so images are not OCR-checked here; CI installs it", tool)
		}
	}
	const blob = "d3f69c36b21fdf97feacffa546efe3a5dcb3189b"
	gif, err := exec.Command("git", "cat-file", "-p", blob).Output()
	if err != nil {
		if os.Getenv("PODPEERS_REQUIRE_OCR") != "" {
			t.Fatalf("the demo blob is required here but not in this clone's history (shallow clone?): %v", err)
		}
		t.Skipf("the demo blob is not in this clone's history (shallow clone?): %v", err)
	}
	// Only the few seconds that show the address, so the test stays quick.
	full, clip := filepath.Join(t.TempDir(), "full.gif"), filepath.Join(t.TempDir(), "clip.gif")
	os.WriteFile(full, gif, 0o644)
	if out, err := exec.Command("ffmpeg", "-v", "error", "-ss", "30", "-t", "3", "-i", full, clip).CombinedOutput(); err != nil {
		t.Fatalf("cutting the frames: %v\n%s", err, out)
	}
	cut, _ := os.ReadFile(clip)
	dir := repo(t, map[string]string{"docs/demo.gif": string(cut)})
	code, out := gate(t, dir)
	if code == 0 || !strings.Contains(out, "rendered in") {
		t.Fatalf("hygiene.sh missed an address rendered in an image (exit %d):\n%s", code, out)
	}
	// Listed as a known, already-public blob, history lets exactly it through.
	known, _ := exec.Command("git", "-C", dir, "rev-parse", "HEAD:docs/demo.gif").Output()
	os.WriteFile(filepath.Join(dir, "hack", "hygiene-history-known.txt"), []byte(strings.TrimSpace(string(known))+" docs/demo.gif test\n"), 0o644)
	if code, out := gate(t, dir, "--history"); code != 0 {
		t.Fatalf("a listed known blob should pass --history: exit %d\n%s", code, out)
	}
}
