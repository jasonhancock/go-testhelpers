package generic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
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
	require.NoError(t, ca.MakeCert(&cert, &key, []string{"127.0.0.1"}))

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

func TestMakeCertKeyTypes(t *testing.T) {
	ca, err := NewCertificateAuthority(WithKeySize(2048))
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		description string
		opts        []CertificateOption
		keyPEMType  string
		check       func(t *testing.T, pub any)
	}{
		{
			"default is 2048 bit RSA",
			nil,
			"RSA PRIVATE KEY",
			func(t *testing.T, pub any) {
				require.IsType(t, &rsa.PublicKey{}, pub)
				require.Equal(t, 2048, pub.(*rsa.PublicKey).N.BitLen())
			},
		},
		{
			"key size honored",
			[]CertificateOption{WithKeySize(3072)},
			"RSA PRIVATE KEY",
			func(t *testing.T, pub any) {
				require.Equal(t, 3072, pub.(*rsa.PublicKey).N.BitLen())
			},
		},
		{
			"ECDSA",
			[]CertificateOption{WithKey(ecKey)},
			"EC PRIVATE KEY",
			func(t *testing.T, pub any) {
				require.True(t, ecKey.PublicKey.Equal(pub))
			},
		},
		{
			"Ed25519",
			[]CertificateOption{WithKey(edKey)},
			"PRIVATE KEY",
			func(t *testing.T, pub any) {
				require.True(t, edKey.Public().(ed25519.PublicKey).Equal(pub))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			var cert, key bytes.Buffer
			require.NoError(t, ca.MakeCert(&cert, &key, []string{"foo.example.com"}, tt.opts...))

			block, _ := pem.Decode(key.Bytes())
			require.NotNil(t, block)
			require.Equal(t, tt.keyPEMType, block.Type)

			// the cert and key must form a usable pair
			_, err := tls.X509KeyPair(cert.Bytes(), key.Bytes())
			require.NoError(t, err)

			block, _ = pem.Decode(cert.Bytes())
			require.NotNil(t, block)
			c, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			require.NoError(t, c.CheckSignatureFrom(ca.Cert))
			tt.check(t, c.PublicKey)
		})
	}
}

func TestSignCertWithKey(t *testing.T) {
	ca, err := NewCertificateAuthority(WithKeySize(2048))
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"foo.example.com"},
	}

	var cert, key bytes.Buffer
	require.NoError(t, ca.SignCert(template, &cert, &key, WithKey(ecKey)))
	_, err = tls.X509KeyPair(cert.Bytes(), key.Bytes())
	require.NoError(t, err)
}

func TestGenerateSelfSignedCertWithKey(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var cert, key bytes.Buffer
	require.NoError(t, GenerateSelfSignedCert(&cert, &key, []string{"foo.example.com"}, WithKey(edKey)))
	_, err = tls.X509KeyPair(cert.Bytes(), key.Bytes())
	require.NoError(t, err)
}

func TestNewCertificateAuthorityWithKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = NewCertificateAuthority(WithKey(ecKey))
	require.Error(t, err)
}

func TestCertificateAuthorityCertIsParsed(t *testing.T) {
	ca, err := NewCertificateAuthority(WithKeySize(2048))
	require.NoError(t, err)
	require.NotEmpty(t, ca.Cert.Raw)
	require.NotEmpty(t, ca.Cert.SubjectKeyId)
	require.True(t, ca.PrivKey.PublicKey.Equal(ca.Cert.PublicKey))

	// Go only sets AuthorityKeyId when the subject differs from the issuer,
	// and leaf certs default to the same subject as the CA.
	var cert, key bytes.Buffer
	require.NoError(t, ca.MakeCert(&cert, &key, []string{"foo.example.com"}, WithSubject(pkix.Name{CommonName: "foo.example.com"})))
	block, _ := pem.Decode(cert.Bytes())
	require.NotNil(t, block)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, ca.Cert.SubjectKeyId, c.AuthorityKeyId)
}
