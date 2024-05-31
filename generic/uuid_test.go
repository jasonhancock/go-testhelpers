package generic

import (
	"testing"

	"github.com/google/uuid"
)

func TestIsUUID(t *testing.T) {
	IsUUID(t, uuid.New().String())
}
