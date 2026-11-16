// Package fixture is the TXE-7549 demonstration tree: its one mutant makes Cleanup run
// `go clean -modcache` with the caller's environment, as the TXE-7538 mutant did (TXE-7547).
package fixture

import "os/exec"

var _ = exec.Command // keeps os/exec imported for the mutant

// Cleanup removes what this package created, which is nothing.
func Cleanup() error {
	return nil // CLEANUP
}
