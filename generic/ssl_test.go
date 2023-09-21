package generic

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	var cert, key bytes.Buffer
	require.NoError(t, GenerateSelfSignedCert(&cert, &key, []string{"foo.example.com", "bar.example.com"}))
	require.Contains(t, cert.String(), "-----BEGIN CERTIFICATE-----")
	require.Contains(t, key.String(), "-----BEGIN RSA PRIVATE KEY-----")
}
