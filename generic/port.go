package generic

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// NewRandomPort identifies a port on the localhost interface for use during tests
// and returns the string in interface:port format.
// It uses similar methodology to how the net/http/httptest server chooses a port.
func NewRandomPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr()
	l.Close()
	return addr.String()
}
