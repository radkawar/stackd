//go:build tools

// Package tools records versions of repository tools that are not part of the
// Go standard library. It is excluded from normal builds.
package tools

import _ "golang.org/x/vuln/cmd/govulncheck"
