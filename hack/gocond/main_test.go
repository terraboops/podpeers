package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const src = `package p

func f(a, b, c bool, x any, n int) int {
	if a && b || c {
		return 1
	}
	for n > 0 {
		n--
	}
	for i := 0; i < n; i++ {
	}
	for {
		break
	}
	switch {
	case a, b:
		return 2
	}
	switch n {
	case 1, 2:
		return 3
	case 4:
	default:
		n = 7
		return 5
	}
	switch x.(type) {
	case int:
		return 6
	}
	if a ||
		b {
		return 8
	}
	ok := a && (b || c)
	_ = ok
	return 0
}
`

func apply(c Cond) string { return src[:c.Start] + c.New + src[c.End:] }

func TestListsEveryConditionAndHowToDisableIt(t *testing.T) {
	conds, err := List("f.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		line       int
		kind       string
		k          int
		was, edits string
	}
	wants := []want{
		{4, "boolop", 0, "&&", "||"},
		{4, "boolop", 1, "||", "&&"},
		{4, "if", 0, "a && b || c", "false && (a && b || c)"},
		{7, "bound", 0, ">", ">="},
		{7, "for", 0, "n > 0", "false && (n > 0)"},
		{10, "bound", 0, "<", "<="},
		{10, "for", 0, "i < n", "false && (i < n)"},
		{16, "case", 0, "a", "false && (a)"},
		{16, "case", 1, "b", "false && (b)"},
		{20, "arm", 0, "\n\t\treturn 3", "\nn = 7\n\t\treturn 5"},
		{22, "arm", 0, "", "\nn = 7\n\t\treturn 5"},
		{28, "arm", 0, "\n\t\treturn 6", ""},
		{31, "boolop", 0, "||", "&&"},
		{31, "if", 0, "a ||\n\t\tb", "false && (a ||\n\t\tb)"},
		{35, "boolop", 0, "&&", "||"},
		{35, "boolop", 1, "||", "&&"},
	}
	if len(conds) != len(wants) {
		t.Fatalf("got %d conditions, want %d: %+v", len(conds), len(wants), conds)
	}
	for i, w := range wants {
		c := conds[i]
		if c.File != "f.go" || c.Line != w.line || c.Kind != w.kind || c.K != w.k || src[c.Start:c.End] != w.was || c.New != w.edits {
			t.Errorf("condition %d: got %+v (span %q), want %+v", i, c, src[c.Start:c.End], w)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), "m.go", apply(c), 0); err != nil {
			t.Errorf("condition %d (%s line %d): the edit does not parse: %v", i, c.Kind, c.Line, err)
		}
	}
}

func TestOffsetsAreBytes(t *testing.T) {
	s := "package p\n\nvar s = \"é→\"\n\nfunc f(a bool) { if a { _ = s } }\n"
	conds, err := List("u.go", []byte(s))
	if err != nil || len(conds) != 1 || s[conds[0].Start:conds[0].End] != "a" {
		t.Fatalf("%v %+v", err, conds)
	}
}

func TestUnparsableSourceIsAnError(t *testing.T) {
	if _, err := List("x.go", []byte("package p\nfunc {")); err == nil {
		t.Fatal("want an error")
	}
}

// Run as a command: one JSON line per condition; a usage error without
// files; a failure for a file it cannot read or parse.
func TestCommand(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gocond")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	f := filepath.Join(t.TempDir(), "f.go")
	os.WriteFile(f, []byte(src), 0o644)
	out, err := exec.Command(bin, f).Output()
	if err != nil || strings.Count(string(out), "\n") != 16 || !strings.Contains(string(out), `"kind":"arm"`) {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{nil, 2, "usage: gocond FILE..."},
		{[]string{filepath.Join(t.TempDir(), "missing.go")}, 1, "no such file"},
		{[]string{writeFile(t, "package p\nfunc {")}, 1, "expected"},
	} {
		cmd := exec.Command(bin, c.args...)
		msg, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != c.code || !strings.Contains(string(msg), c.msg) {
			t.Errorf("%v: exit %d, want %d with %q:\n%s", c.args, cmd.ProcessState.ExitCode(), c.code, c.msg, msg)
		}
	}
}

func writeFile(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "bad.go")
	os.WriteFile(p, []byte(body), 0o644)
	return p
}

// A default arm with no statements gives the other arms an empty body.
func TestAnEmptyDefaultEmptiesTheArms(t *testing.T) {
	s := "package p\n\nfunc f(n int) int {\n\tswitch n {\n\tcase 1:\n\t\treturn 1\n\tdefault:\n\t}\n\treturn 0\n}\n"
	conds, err := List("e.go", []byte(s))
	if err != nil || len(conds) != 1 || conds[0].Kind != "arm" || conds[0].New != "" {
		t.Fatalf("%v %+v", err, conds)
	}
}

// Each comparison's boundary moves by one, both ways; == and != are left
// to the condition-level mutations.
func TestBoundariesMoveByOne(t *testing.T) {
	s := "package p\n\nfunc f(a, b int) bool { return a < b || a <= b || a > b || a >= b || a == b || a != b }\n"
	conds, err := List("b.go", []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range conds {
		if c.Kind == "bound" {
			got = append(got, s[c.Start:c.End]+">"+c.New)
		}
	}
	if strings.Join(got, " ") != "<><= <=>< >>>= >=>>" {
		t.Fatalf("boundaries: %v", got)
	}
}
