/*
Copyright 2021 Intel Coporation.
SPDX-License-Identifier: Apache-2.0
*/

package k8sutil

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	namespaceEnvVar = "WATCH_NAMESPACE"
	namespaceFile   = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// GetNamespace returns the namespace of the operator pod
func GetNamespace() string {
	ns := os.Getenv(namespaceEnvVar)
	if ns == "" {
		// If environment variable not set, give it a try to fetch it from
		// mounted filesystem by Kubernetes
		data, err := ioutil.ReadFile(namespaceFile)
		if err != nil {
			klog.Infof("Could not read namespace from %q: %v", namespaceFile, err)
		} else {
			ns = string(data)
		}
	}

	if ns == "" {
		ns = metav1.NamespaceDefault
	}

	return ns
}

func CreateCASecret(ctx context.Context, c client.Client, cert *x509.Certificate, name, ns string) error {
	if ns == "" {
		ns = GetNamespace()
	}
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Type: v1.SecretTypeTLS,
		Data: map[string][]byte{
			v1.TLSPrivateKeyKey: []byte(""),
			v1.TLSCertKey:       tlsutil.EncodeCert(cert),
		},
	}
	err := c.Create(ctx, secret)
	if err != nil && errors.IsAlreadyExists(err) {
		return c.Update(ctx, secret)
	}
	return err
}

func DeleteCASecret(ctx context.Context, c client.Client, name, ns string) error {
	if ns == "" {
		ns = GetNamespace()
	}
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
	}

	err := c.Delete(ctx, secret)
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	return err
}

func QuoteAttestationDeliver(
	ctx context.Context,
	c client.Client,
	instanceName, namespace string,
	requestType tcsapi.QuoteAttestationRequestType,
	signerNames []string,
	quote []byte,
	quotePubKey interface{},
	tokenLabel string) error {

	encPubKey, err := tlsutil.EncodePublicKey(quotePubKey)
	if err != nil {
		return err
	}

	encQuote := base64.StdEncoding.EncodeToString(quote)

	if namespace == "" {
		namespace = GetNamespace()
	}

	sgxAttestation := &tcsapi.QuoteAttestation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instanceName,
			Namespace: namespace,
		},
		Spec: v1alpha1.QuoteAttestationSpec{
			Type:         requestType,
			Quote:        []byte(encQuote),
			QuoteVersion: tcsapi.ECDSAQuoteVersion3,
			SignerNames:  signerNames,
			ServiceID:    tokenLabel,
			PublicKey:    encPubKey,
		},
	}

	//Create a CR instance for QuoteAttestation
	//If not found object, return a new one
	err = c.Create(ctx, sgxAttestation)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			if err = c.Delete(ctx, sgxAttestation); err != nil {
				return fmt.Errorf("failed to delete existing QuoteAttestaion CR with name '%s'. Clear this before redeploy the operator: %v", instanceName, err)
			}

			err = c.Create(ctx, sgxAttestation)
		}
	}
	return err
}

func QuoteAttestationDelete(ctx context.Context, c client.Client, instanceName string, ns string) error {
	if ns == "" {
		ns = GetNamespace()
	}
	sgxAttestation := &tcsapi.QuoteAttestation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instanceName,
			Namespace: ns,
		},
	}

	err := c.Delete(ctx, sgxAttestation)
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	return err
}

// Converts signer name to valid Kubernetes object name
//  Ex:- intel.com/tcs -> tcs.intel.com
//       tcsissuer.tcs.intel.com/sgx-ca1 -> sgx-ca1.tcsissuer.intel.tcs.com
func SignerNameToResourceName(signerName string) string {
	slices := strings.SplitN(signerName, "/", 2)
	if len(slices) == 2 {
		return slices[1] + "." + slices[0]
	}

	return slices[0]
}
