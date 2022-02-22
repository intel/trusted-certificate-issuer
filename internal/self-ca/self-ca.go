/*
Copyright 2021 Intel(R)
SPDX-License-Identifier: Apache-2.0
*/

package selfca

import (
	"crypto"
	"errors"
	"fmt"
	"runtime"
	"time"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	cmpki "github.com/jetstack/cert-manager/pkg/util/pki"
)

var (
	CertificateExpiredError     = errors.New("expired")
	CertificateInvalidDateError = errors.New("invalid date")
	CertificateIsNotCAError     = errors.New("certificate is not for CA")
	CertificateInvalidError     = errors.New("invalid")
)

// CA type representation for a self-signed certificate authority
type CA struct {
	prKey crypto.Signer
	cert  *x509.Certificate
}

// NewCA creates a new CA object for given CA certificate and private key.
// If both of caCert and key are nil, generates a new private key and
// a self-signed certificate
func NewCA(key crypto.Signer, cert *x509.Certificate) (*CA, error) {
	if key == nil {
		return nil, fmt.Errorf("no key provided")
	}

	if cert == nil {
		return nil, fmt.Errorf("no CA certificate provided")
	}

	if err := ValidateCACertificate(cert, key.Public()); err != nil {
		return nil, err
	}

	ca := &CA{
		prKey: key,
		cert:  cert,
	}
	return ca, nil
}

// PrivateKey returns private key used
func (ca *CA) PrivateKey() crypto.Signer {
	if ca == nil {
		return nil
	}
	return ca.prKey
}

// Certificate returns root ca certificate used
func (ca *CA) Certificate() *x509.Certificate {
	if ca == nil {
		return nil
	}
	return ca.cert
}

// EncodedKey returns encoded private key used
func (ca *CA) EncodedKey() []byte {
	if ca == nil {
		return nil
	}
	return tlsutil.EncodeKey(nil)
}

// EncodedCertificate returns encoded root ca certificate used
func (ca *CA) EncodedCertificate() []byte {
	if ca == nil {
		return nil
	}
	return tlsutil.EncodeCert(ca.cert)
}

func (ca *CA) Sign(csrPEM []byte, keyUsage x509.KeyUsage, extKeyUsage []x509.ExtKeyUsage, extensions []pkix.Extension) (*x509.Certificate, error) {
	if ca == nil {
		return nil, fmt.Errorf("nil CA")
	}

	duration := time.Hour * 24 * 365 // 1 year
	tmpl, err := cmpki.GenerateTemplateFromCSRPEMWithUsages(csrPEM, duration, false, keyUsage, extKeyUsage)
	if err != nil {
		return nil, fmt.Errorf("failed generating certificate template: %v", err)
	}
	tmpl.Issuer = ca.cert.Issuer
	tmpl.Version = tls.VersionTLS12
	tmpl.ExtraExtensions = extensions

	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, tmpl.PublicKey, ca.prKey)
	*tmpl = x509.Certificate{}
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %v", err)
	}

	runtime.SetFinalizer(cert, func(c *x509.Certificate) {
		*c = x509.Certificate{}
	})

	return cert, nil
}

func ValidateCACertificate(cert *x509.Certificate, key crypto.PublicKey) error {
	res := false
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		res = pub.Equal(key)
	case *ecdsa.PublicKey:
		res = pub.Equal(key)
	case ed25519.PublicKey:
		res = pub.Equal(key)
	}
	if !res {
		return fmt.Errorf("mismatched CA key and certificate")
	}

	if time.Now().Before(cert.NotBefore) {
		return CertificateInvalidDateError
	}

	if time.Now().UTC().After(cert.NotAfter) {
		return CertificateExpiredError
	}

	if !cert.IsCA {
		return CertificateIsNotCAError
	}

	//if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
	//	return fmt.Errorf("%s: CA certificate is not intended for certificate signing", CertificateInvalidError)
	//}

	return nil
}
