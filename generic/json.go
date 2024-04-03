package generic

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// RequireJSONValue takes a JSON string as input, then checks that the key
// matches the value.
func RequireJSONValue(t *testing.T, input, key string, value any) {
	t.Helper()
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(input), &data))
	require.Contains(t, data, key)
	require.Equal(t, value, data[key])
}
