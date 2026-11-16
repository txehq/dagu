package fixture

import (
	"os"
	"testing"
)

// The test passes whatever Cleanup does, so the cleanup mutant survives: deleting a cache is not
// a kill. It logs what Cleanup returned and whether the module cache its environment names still
// exists afterwards, so a run's output shows what the mutant actually did (run with -v).
func TestCleanup(t *testing.T) {
	err := Cleanup()
	t.Logf("cleanup returned: %v", err)
	dir := os.Getenv("GOMODCACHE")
	_, statErr := os.Stat(dir)
	t.Logf("GOMODCACHE %s after cleanup: exists=%v (%v)", dir, statErr == nil, statErr)
}
