package testutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"time"
)

func NewCACertificate(key crypto.Signer, validFrom time.Time, duration time.Duration, isCA bool) (*x509.Certificate, error) {
	max := new(big.Int).SetInt64(math.MaxInt64)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Version:               tls.VersionTLS12,
		SerialNumber:          serial,
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(duration).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			CommonName:   "test root certificate authority",
			Organization: []string{"Go test"},
		},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certBytes)
}

func NewCertificateRequest(key crypto.Signer, subject pkix.Name) ([]byte, error) {
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
	}

	var alog x509.SignatureAlgorithm
	switch key.(type) {
	case *rsa.PrivateKey:
		alog = x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		alog = x509.ECDSAWithSHA256
	}

	template := &x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: alog,
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

func EncodeCSR(csr []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}
