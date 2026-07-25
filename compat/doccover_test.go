package compat

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"testing"
)

// TestMigrationDocCoversV1API parses the v1 sources and asserts that
// every exported identifier (functions, methods, types, exported struct
// fields, constants) appears somewhere in ../MIGRATION.md, so the
// "every v1 identifier appears in the reference" promise is machine
// checked instead of hand maintained.
func TestMigrationDocCoversV1API(t *testing.T) {
	docBytes, err := os.ReadFile("../MIGRATION.md")
	if err != nil {
		t.Fatalf("reading MIGRATION.md: %v", err)
	}
	doc := string(docBytes)

	fset := token.NewFileSet()
	var idents []string
	for _, path := range []string{"../../go-pcre/pcre.go", "../../go-pcre/consts.go"} {
		af, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing v1 source %s: %v", path, err)
		}
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl: // package functions and methods alike
				if d.Name.IsExported() {
					idents = append(idents, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec: // consts and vars
						for _, n := range s.Names {
							if n.IsExported() {
								idents = append(idents, n.Name)
							}
						}
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						idents = append(idents, s.Name.Name)
						st, ok := s.Type.(*ast.StructType)
						if !ok {
							continue
						}
						for _, fld := range st.Fields.List {
							for _, n := range fld.Names {
								if n.IsExported() {
									idents = append(idents, n.Name)
								}
							}
						}
					}
				}
			}
		}
	}

	seen := map[string]bool{}
	for _, id := range idents {
		if seen[id] {
			continue
		}
		seen[id] = true
		wordRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`)
		if !wordRe.MatchString(doc) {
			t.Errorf("v1 exported identifier %q does not appear in MIGRATION.md", id)
		}
	}
	t.Logf("checked %d unique exported v1 identifiers against MIGRATION.md", len(seen))
}
