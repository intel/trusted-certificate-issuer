/*
Copyright 2021 Intel Coporation.
SPDX-License-Identifier: Apache-2.0
*/

package k8sutil

import (
	"context"
	"crypto/x509"
	"io/ioutil"
	"os"
	"strings"

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
