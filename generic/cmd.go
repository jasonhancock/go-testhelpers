package generic

import (
	"fmt"
	"os/exec"
	"testing"
)

// MustCommand executes the command and requires a clean exit code.
func MustCommand(t *testing.T, command string, args ...string) {
	b, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		t.Fatal(fmt.Errorf("command failed: %q %w", string(b), err))
	}
}
