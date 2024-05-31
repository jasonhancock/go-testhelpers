package generic

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func IsUUID(t *testing.T, str string) {
	_, err := uuid.Parse(str)
	require.NoError(t, err)
}
