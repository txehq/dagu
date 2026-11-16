package fixture

import "testing"

// The test passes whatever Cleanup does, so the cleanup mutant survives: deleting a cache is not
// a kill.
func TestCleanup(t *testing.T) { _ = Cleanup() }
