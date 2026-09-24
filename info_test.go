package pcre

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestInfo(t *testing.T) {
	re := MustCompile(`(?<a>abc)(d)?`, 0)

	want := map[string]struct {
		key int
		val uint64
	}{
		"capturecount":  {INFO_CAPTURECOUNT, uint64(re.Groups())},
		"minlength":     {INFO_MINLENGTH, 3},
		"namecount":     {INFO_NAMECOUNT, 1},
		"maxlookbehind": {INFO_MAXLOOKBEHIND, 0},
		"jitsize":       {INFO_JITSIZE, 0}, // not studied yet
	}
	for name, w := range want {
		got, err := re.Info(w.key)
		if err != nil || got != w.val {
			t.Errorf("Info(%s) = %d, %v; want %d", name, got, err, w.val)
		}
	}

	// INFO_SIZE is size_t-valued and must come back through the wide path.
	if size, err := re.Info(INFO_SIZE); err != nil || size == 0 {
		t.Errorf("Info(INFO_SIZE) = %d, %v; want a non-zero size", size, err)
	}

	for _, key := range []int{INFO_NAMETABLE, INFO_FIRSTBITMAP, 9999} {
		if _, err := re.Info(key); err == nil {
			t.Errorf("Info(%d): want an error for a pointer-valued or unknown key", key)
		}
	}

	if JITAvailable() {
		if err := re.Study(JIT_COMPLETE); err != nil {
			t.Fatal(err)
		}
		if size, err := re.Info(INFO_JITSIZE); err != nil || size == 0 {
			t.Errorf("Info(INFO_JITSIZE) after Study = %d, %v; want non-zero", size, err)
		}
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("Info on a zero Regexp: want a panic")
		}
	}()
	var zero Regexp
	_, _ = zero.Info(INFO_MINLENGTH)
}

// infoIdents returns the INFO_* identifiers appearing in a source file:
// declared constants in consts.go, referenced keys in info.go.
func infoIdents(t *testing.T, file string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && strings.HasPrefix(id.Name, "INFO_") {
			names[id.Name] = true
		}

		return true
	})

	return names
}

func TestInfoCoversEveryInfoConstant(t *testing.T) {
	// The exported INFO_* set (consts.go) and the keys Info decides a width
	// for (info.go) are two lists kept in step by hand; a constant missing
	// from Info would fail at run time as "unknown pattern info key".
	declared := infoIdents(t, "consts.go")
	handled := infoIdents(t, "info.go")
	for name := range declared {
		if !handled[name] {
			t.Errorf("%s is exported in consts.go but Info does not handle it", name)
		}
	}
	for name := range handled {
		if !declared[name] {
			t.Errorf("Info handles %s, which consts.go does not export", name)
		}
	}
	if len(declared) == 0 {
		t.Fatal("no INFO_ constants found in consts.go")
	}
}
