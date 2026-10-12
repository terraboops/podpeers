// Command gocond lists every condition in Go source files, by the Go parser,
// for hack/guard-sweep.py: one JSON object per line with the condition's file,
// line, kind, its index k among conditions of that kind on that line, and the
// byte span to replace and its replacement, so that applying it disables
// exactly that condition.
//
//	go run ./hack/gocond FILE...
//
// Kinds and how each is disabled:
//
//	if, for, case   an if or for condition, or a tagless switch case's
//	                expression: replaced by `false && (<cond>)`
//	boolop          one && or ||: flipped to the other
//	arm             an arm of a tagged or type switch: its body replaced by
//	                the default arm's (or none), so its values fall through
//	                to what the switch does without it
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
)

// Cond is one condition and the edit that disables it.
type Cond struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	K     int    `json:"k"`
	Start int    `json:"start"` // byte offset in the file
	End   int    `json:"end"`
	New   string `json:"new"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gocond FILE...")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	for _, path := range os.Args[1:] {
		src, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		conds, err := List(path, src)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, c := range conds {
			enc.Encode(c)
		}
	}
}

// List returns every condition in src, ordered by line, kind and position.
func List(path string, src []byte) ([]Cond, error) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, path, src, 0)
	if err != nil {
		return nil, err
	}
	off := func(p token.Pos) int { return fs.Position(p).Offset }
	text := func(a, b token.Pos) string { return string(src[off(a):off(b)]) }
	type raw struct {
		Cond
		at int // position on the line, for ordering
	}
	var out []raw
	add := func(kind string, at token.Pos, start, end int, repl string) {
		out = append(out, raw{Cond{File: path, Line: fs.Position(at).Line, Kind: kind, Start: start, End: end, New: repl}, off(at)})
	}
	disable := func(kind string, e ast.Expr) {
		add(kind, e.Pos(), off(e.Pos()), off(e.End()), "false && ("+text(e.Pos(), e.End())+")")
	}
	arms := func(body *ast.BlockStmt) {
		var deflt string
		for _, s := range body.List {
			if cc := s.(*ast.CaseClause); cc.List == nil {
				deflt = clauseBody(src, off, cc)
			}
		}
		for _, s := range body.List {
			cc := s.(*ast.CaseClause)
			if cc.List == nil {
				continue
			}
			start := off(cc.Colon) + 1
			end := start
			if len(cc.Body) > 0 {
				end = off(cc.Body[len(cc.Body)-1].End())
			}
			repl := ""
			if deflt != "" {
				repl = "\n" + deflt
			}
			add("arm", cc.Pos(), start, end, repl)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			disable("if", x.Cond)
		case *ast.ForStmt:
			if x.Cond != nil {
				disable("for", x.Cond)
			}
		case *ast.SwitchStmt:
			if x.Tag == nil {
				for _, s := range x.Body.List {
					for _, e := range s.(*ast.CaseClause).List {
						disable("case", e)
					}
				}
			} else {
				arms(x.Body)
			}
		case *ast.TypeSwitchStmt:
			arms(x.Body)
		case *ast.BinaryExpr:
			if x.Op == token.LAND || x.Op == token.LOR {
				flip := "||"
				if x.Op == token.LOR {
					flip = "&&"
				}
				add("boolop", x.OpPos, off(x.OpPos), off(x.OpPos)+2, flip)
			}
		}
		return true
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].at < out[j].at
	})
	seen := map[string]int{}
	conds := make([]Cond, len(out))
	for i, r := range out {
		key := fmt.Sprintf("%d/%s", r.Line, r.Kind)
		r.K = seen[key]
		seen[key]++
		conds[i] = r.Cond
	}
	return conds, nil
}

// clauseBody is the source of a case clause's statements, or "" if none.
func clauseBody(src []byte, off func(token.Pos) int, cc *ast.CaseClause) string {
	if len(cc.Body) == 0 {
		return ""
	}
	return string(bytes.TrimSpace(src[off(cc.Colon)+1 : off(cc.Body[len(cc.Body)-1].End())]))
}
