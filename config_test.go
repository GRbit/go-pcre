package pcre

import (
	"strconv"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	// PCRE2's numeric config outputs are uniformly uint32, so v1's
	// buffer-width test (bug #6, unsigned long vs int) has no PCRE2
	// counterpart; a value sanity check remains.
	ml, err := strconv.ParseUint(Config(CONFIG_MATCHLIMIT), 10, 64)
	if err != nil || ml == 0 {
		t.Errorf("Config(CONFIG_MATCHLIMIT) = %q, want a positive number", Config(CONFIG_MATCHLIMIT))
	}

	ver := Config(CONFIG_VERSION)
	if !strings.HasPrefix(ver, "10.") {
		t.Errorf("Config(CONFIG_VERSION) = %q, want a 10.x version", ver)
	}

	uni := Config(CONFIG_UNICODE_VERSION)
	if uni == "" {
		t.Errorf("Config(CONFIG_UNICODE_VERSION) is empty")
	}

	// JITTARGET answers BADOPTION on a JIT-less library; Config renders
	// that as "" instead of failing.
	target := Config(CONFIG_JITTARGET)
	if JITAvailable() && target == "" {
		t.Error("JIT is available but Config(CONFIG_JITTARGET) is empty")
	}
	if !JITAvailable() && target != "" {
		t.Errorf("JIT unavailable but JITTARGET = %q", target)
	}

	if got := Config(-1); got != "" {
		t.Errorf("Config(-1) = %q, want \"\" for an unknown key", got)
	}
}

func TestConfigAll(t *testing.T) {
	all := ConfigAll()
	for _, want := range []string{
		"jit: ", "version: " + Config(CONFIG_VERSION),
		"match_limit: " + Config(CONFIG_MATCHLIMIT),
		"depth_limit: ", "unicode: 1",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("ConfigAll() missing %q:\n%s", want, all)
		}
	}
}
