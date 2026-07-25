module github.com/GRbit/go-pcre/v2/compat

go 1.24

require (
	github.com/GRbit/go-pcre v1.0.1
	github.com/GRbit/go-pcre/v2 v2.0.0
)

// The differential suite compares the local v2 sources (the parent
// directory) against the local v1 sources: a sibling checkout of this
// repository with the pcre8.x branch checked out. See README.md.
replace github.com/GRbit/go-pcre => ../../go-pcre

replace github.com/GRbit/go-pcre/v2 => ..
