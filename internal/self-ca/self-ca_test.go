/*
Copyright 2021 Intel(R)
SPDX-License-Identifier: Apache-2.0
*/
package selfca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	selfca "github.com/intel/trusted-certificate-issuer/internal/self-ca"
	testutils "github.com/intel/trusted-certificate-issuer/test/utils"
	"github.com/stretchr/testify/require"
)

func TestSelfCA(t *testing.T) {
	t.Run("missing CA key or certificate", func(t *testing.T) {
		ca, err := selfca.NewCA(nil, nil)
		require.Nil(t, ca, "missing ca key or certificate should result in nil ca")
		require.Error(t, err, "expected an error")

		key, err := rsa.GenerateKey(rand.Reader, 3072)
		require.NoError(t, err, "failed to create rsa key")
		ca, err = selfca.NewCA(key, nil)
		require.Nil(t, ca, "missing ca certificate should result in nil ca")
		require.Error(t, err, "expected an error")

		cert, err := testutils.NewCACertificate(key, time.Now(), time.Hour, true)
		require.NoError(t, err, "failed to create CA certificate")
		ca, err = selfca.NewCA(nil, cert)
		require.Nil(t, ca, "missing ca certificate should result in nil ca")
		require.Error(t, err, "expected an error")

		ca, err = selfca.NewCA(key, cert)
		require.NoError(t, err, "expected no error")
		require.NotNil(t, ca, "nil ca")
	})

	t.Run("must fail for invalidate certificate", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		require.NoError(t, err, "failed to create rsa key")
		otherKey, err := rsa.GenerateKey(rand.Reader, 3072)
		require.NoError(t, err, "failed to create rsa key")

		cert, err := testutils.NewCACertificate(key, time.Now(), time.Hour, true)
		require.NoError(t, err, "failed to create CA certificate")

		// mismatched key and certificate
		ca, err := selfca.NewCA(otherKey, cert)
		require.Nil(t, ca, "missing ca certificate should result in nil ca")
		require.Error(t, err, "expected an error")

		cert, err = testutils.NewCACertificate(key, time.Now(), time.Hour, false)
		require.NoError(t, err, "failed to create CA certificate")

		// certificate.isCA is false
		ca, err = selfca.NewCA(key, cert)
		require.Nil(t, ca, "certificate.isCA false")
		require.ErrorIs(t, err, selfca.CertificateIsNotCAError)

		// certificate.NotBefore current time
		cert, err = testutils.NewCACertificate(key, time.Now().Add(2*time.Hour), time.Hour, true)
		require.NoError(t, err, "failed to create CA certificate")
		ca, err = selfca.NewCA(key, cert)
		require.Nil(t, ca, "certificate.isCA false")
		require.ErrorIs(t, err, selfca.CertificateInvalidDateError)

		// expired certificate (NotAfter < current time)
		cert, err = testutils.NewCACertificate(key, time.Now().Add(-3*time.Hour), 2*time.Hour, true)
		require.NoError(t, err, "failed to create CA certificate")
		ca, err = selfca.NewCA(key, cert)
		require.Nil(t, ca, "certificate.isCA false")
		require.ErrorIs(t, err, selfca.CertificateExpiredError)
	})

	t.Run("sign client certificate", func(t *testing.T) {
		caKey, err := rsa.GenerateKey(rand.Reader, 3072)
		require.NoError(t, err, "failed to create rsa key")

		caCert, err := testutils.NewCACertificate(caKey, time.Now(), time.Hour, true)
		require.NoError(t, err, "failed to create CA certificate")

		// mismatched key and certificate
		ca, err := selfca.NewCA(caKey, caCert)
		require.NoError(t, err, "create CA")
		require.NotNil(t, ca, "create CA")

		// Key to be signed by the CA
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "create key")

		csrBytes, err := testutils.NewCertificateRequest(key, pkix.Name{CommonName: "client-service"})
		require.NoError(t, err, "create CSR")

		_, err = ca.Sign(testutils.EncodeCSR(csrBytes), x509.KeyUsageCRLSign, nil, nil)
		require.NoError(t, err, "sign client certificate")
	})
}
