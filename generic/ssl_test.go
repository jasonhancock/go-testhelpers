package generic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	var cert, key bytes.Buffer
	require.NoError(t, GenerateSelfSignedCert(&cert, &key, []string{"foo.example.com", "bar.example.com", "127.0.0.1"}))
	require.Contains(t, cert.String(), "-----BEGIN CERTIFICATE-----")
	require.Contains(t, key.String(), "-----BEGIN RSA PRIVATE KEY-----")

	block, _ := pem.Decode(cert.Bytes())
	require.NotNil(t, block)

	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, []string{"foo.example.com", "bar.example.com"}, certificate.DNSNames)
	require.Len(t, certificate.IPAddresses, 1)
	require.Equal(t, "127.0.0.1", certificate.IPAddresses[0].String())
}

func TestCA(t *testing.T) {
	ca, err := NewCertificateAuthority()
	require.NoError(t, err)

	var cert, key bytes.Buffer
	require.NoError(t, ca.MakeCert(&cert, &key, "127.0.0.1"))

	serverCert, err := tls.X509KeyPair(cert.Bytes(), key.Bytes())
	require.NoError(t, err)

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	port := NewRandomPort(t)

	server := http.Server{
		Addr: port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		}),
		TLSConfig: serverTLSConf,
	}

	go func() {
		err := server.ListenAndServeTLS("", "")
		if err != nil && err == http.ErrServerClosed {
			return
		}
		require.NoError(t, err)
	}()

	defer func() {
		sdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, server.Shutdown(sdCtx))
	}()

	time.Sleep(500 * time.Millisecond) // give things time to start up.

	certpool := x509.NewCertPool()
	require.True(t, certpool.AppendCertsFromPEM(ca.PEMCert))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		},
	}

	resp, err := client.Get("https://" + port)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), b)
}
