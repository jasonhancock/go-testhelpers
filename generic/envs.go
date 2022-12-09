package generic

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// SetEnvs sets environment variables, preserving any existing values from the
// envioronment, and restoring when the test is finished.
func SetEnvs(t *testing.T, envs map[string]string) func(t *testing.T) {
	original := map[string]string{}

	for name, value := range envs {
		if val, ok := os.LookupEnv(name); ok {
			original[name] = val
		}
		require.NoError(t, os.Setenv(name, value))
	}

	return func(t *testing.T) {
		for name := range envs {
			val, ok := original[name]
			if ok {
				require.NoError(t, os.Setenv(name, val))
			} else {
				require.NoError(t, os.Unsetenv(name))
			}
		}
	}
}
