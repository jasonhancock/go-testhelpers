package generic

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

func publicKey(priv interface{}) (any, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, errors.New("unknown private key type")
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal ECDSA private key: %v", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, errors.New("unknwn private key type")
	}
}

func generateTemplate(hosts []string, opts certificateOptions) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: opts.notBefore,
		NotAfter:  opts.notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	return &template
}

// GenerateSelfSignedCert generates a self-signed RSA certificate for testing purposes.
func GenerateSelfSignedCert(destCert, destKey io.Writer, hosts []string, opts ...CertificateOption) error {
	opt := newCertOptions(2048, opts...)

	priv, err := rsa.GenerateKey(rand.Reader, opt.keySize)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}
	template := generateTemplate(hosts, opt)
	pubKey, err := publicKey(priv)
	if err != nil {
		return fmt.Errorf("getting public key: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, priv)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	if err := pem.Encode(destCert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("pem encoding cert: %w", err)
	}

	privPem, err := pemBlockForKey(priv)
	if err != nil {
		return fmt.Errorf("getting private key pem: %w", err)
	}

	if err := pem.Encode(destKey, privPem); err != nil {
		return fmt.Errorf("pem encoding cert: %w", err)
	}

	return nil
}

// CertificateAuthority is a test CA that is capable of signing certs for use during testing.
type CertificateAuthority struct {
	Cert    *x509.Certificate
	PrivKey *rsa.PrivateKey

	PEMCert []byte
	PEMKey  []byte
}

// LoadCertificateAuthority loads a CA from two io.Readers.
func LoadCertificateAuthority(cert, key io.Reader) (*CertificateAuthority, error) {
	var ca CertificateAuthority

	var err error
	ca.PEMCert, err = io.ReadAll(cert)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	ca.PEMKey, err = io.ReadAll(key)
	if err != nil {
		return nil, fmt.Errorf("loading key: %w", err)
	}

	{ // load the certificate
		block, _ := pem.Decode(ca.PEMCert)
		if block == nil {
			return nil, errors.New("unable to decode cert pem block")
		}

		ca.Cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing x509 cert: %w", err)
		}
	}

	{ // load the private key
		block, _ := pem.Decode(ca.PEMKey)
		if block == nil {
			return nil, errors.New("unable to decode key pem block")
		}

		ca.PrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing x509 private key: %w", err)
		}
	}

	return &ca, nil
}

// LoadCertificateAuthorityFiles loads a CA from a cert and key on disk.
func LoadCertificateAuthorityFiles(cert, key string) (*CertificateAuthority, error) {
	certFile, err := os.Open(cert)
	if err != nil {
		return nil, fmt.Errorf("opening ca cert: %w", err)
	}
	defer certFile.Close()

	keyFile, err := os.Open(key)
	if err != nil {
		return nil, fmt.Errorf("opening ca key: %w", err)
	}
	defer keyFile.Close()

	return LoadCertificateAuthority(certFile, keyFile)
}

// NewCertificateAuthority initializes a CertificateAuthority.
func NewCertificateAuthority(opts ...CertificateOption) (*CertificateAuthority, error) {
	opt := newCertOptions(4096, opts...)

	var ca CertificateAuthority
	ca.Cert = &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             opt.notBefore,
		NotAfter:              opt.notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	var err error
	ca.PrivKey, err = rsa.GenerateKey(rand.Reader, opt.keySize)
	if err != nil {
		return nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca.Cert, ca.Cert, &ca.PrivKey.PublicKey, ca.PrivKey)
	if err != nil {
		return nil, err
	}

	// pem encode
	var caPEM bytes.Buffer
	if err := pem.Encode(&caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		return nil, err
	}
	ca.PEMCert = caPEM.Bytes()

	var caPrivKeyPEM bytes.Buffer
	err = pem.Encode(&caPrivKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.PrivKey)})
	if err != nil {
		return nil, err
	}
	ca.PEMKey = caPrivKeyPEM.Bytes()

	return &ca, nil
}

// SignCert will sign a certificate with the CA. This method gives you more
// control of the cert than the MakeCert method does.
func (c *CertificateAuthority) SignCert(template *x509.Certificate, destCert, destKey io.Writer) error {
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, c.Cert, &certPrivKey.PublicKey, c.PrivKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(destCert, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return err
	}

	err = pem.Encode(destKey, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return err
}

// MakeCert is a helper method that will generate a cert using the hosts and/or
// ips in the hosts array.
func (c *CertificateAuthority) MakeCert(destCert, destKey io.Writer, hosts []string, opts ...CertificateOption) error {
	opt := newCertOptions(2048, opts...)
	return c.SignCert(generateTemplate(hosts, opt), destCert, destKey)
}

type certificateOptions struct {
	keySize   int
	notBefore time.Time
	notAfter  time.Time
}

func newCertOptions(keySize int, opts ...CertificateOption) certificateOptions {
	now := time.Now()
	opt := certificateOptions{
		keySize:   keySize,
		notBefore: now,
		notAfter:  now.Add(time.Hour * 24 * 180),
	}
	for _, o := range opts {
		o(&opt)
	}

	return opt
}

// CertificateOption is used to customize certs.
type CertificateOption func(*certificateOptions)

// WithKeySize sets the key size in bits.
func WithKeySize(size int) CertificateOption {
	return func(o *certificateOptions) {
		o.keySize = size
	}
}

// WithNotBefore sets when the certificate becomes valid.
func WithNotBefore(ts time.Time) CertificateOption {
	return func(o *certificateOptions) {
		o.notBefore = ts
	}
}

// WithNotAfter sets the certificate expiration.
func WithNotAfter(ts time.Time) CertificateOption {
	return func(o *certificateOptions) {
		o.notAfter = ts
	}
}
