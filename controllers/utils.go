/*
Copyright 2021 Intel(R).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package controllers

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/internal/k8sutil"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/sgxutils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type IssuerRef struct {
	types.NamespacedName
	Kind string
}

func IssuerSpecAndStatus(issuer client.Object) (*tcsapi.TCSIssuerSpec, *tcsapi.TCSIssuerStatus, error) {
	switch t := issuer.(type) {
	case *tcsapi.TCSIssuer:
		return &t.Spec, &t.Status, nil
	case *tcsapi.TCSClusterIssuer:
		return &t.Spec, &t.Status, nil
	}
	return nil, nil, fmt.Errorf("unrecognized issuer type")
}

func SignerNameForIssuer(issuerGVK schema.GroupVersionKind, name, ns string) string {
	if issuerGVK.Kind == "TCSClusterIssuer" {
		ns = "" // Ignore namespace for cluster-scoped type
	}
	signerName := strings.ToLower(issuerGVK.GroupKind().String()) + "/"
	if ns != "" {
		return signerName + ns + "." + name
	}
	return signerName + name
}

func IssuerRefForSignerName(signerName string) *IssuerRef {
	parts := strings.SplitN(signerName, "/", 2)
	if len(parts) != 2 {
		return nil
	}

	kindGroup := strings.SplitN(parts[0], ".", 2)
	if len(kindGroup) != 2 {
		return nil
	}
	if kindGroup[1] != tcsapi.GroupName {
		return nil
	}

	issuer := &IssuerRef{}
	switch strings.ToLower(kindGroup[0]) {
	case "tcsissuer", "tcsissuers":
		issuer.Kind = "TCSIssuer"
	case "tcsclusterissuer", "tcsclusterissuers":
		issuer.Kind = "TCSClusterIssuer"
	default:
		return nil
	}

	nameParts := strings.SplitN(parts[1], ".", 2)
	if len(nameParts) == 2 {
		issuer.Namespace = nameParts[0]
		issuer.Name = nameParts[1]
	} else {
		issuer.Name = nameParts[0]
	}

	return issuer
}

func GetIssuer(ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	issuerRef *IssuerRef) (client.Object, error) {
	typeMeta := metav1.TypeMeta{
		Kind:       issuerRef.Kind,
		APIVersion: tcsapi.GroupVersion.String(),
	}
	var issuer client.Object
	switch issuerRef.Kind {
	case "TCSClusterIssuer":
		issuer = &tcsapi.TCSClusterIssuer{TypeMeta: typeMeta}
	case "TCSIssuer":
		issuer = &tcsapi.TCSIssuer{TypeMeta: typeMeta}
	default:
		return nil, fmt.Errorf("unknown issuer kind '%s'", issuerRef.Kind)
	}

	// Get the Issuer or ClusterIssuer
	if err := c.Get(ctx, issuerRef.NamespacedName, issuer); err != nil {
		return nil, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	return issuer, nil
}

var (
	// FIXME (avalluri): These identifiers needs to be in sync with
	// values defined in intel/Istio:
	// https://github.com/intel/istio/blob/release-1.15-intel/security/pkg/nodeagent/sds/sgxconfig.go#L57-L58
	// https://github.com/intel/trusted-certificate-issuer/issues/70
	//
	// oidQuote represents the ASN.1 OBJECT IDENTIFIER for the SGX quote
	// and quote validation result.
	oidQuote = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1283}
	// oidQuotePublicKey represents the ASN.1 OBJECT IDENTIFIER for the
	// public key used for generating the SGX quote.
	oidQuotePublicKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1284}
	// oidQuoteNonce represents the ASN.1 OBJECT IDENTIFIER for the
	// nonce used for generating the SGX quote.
	oidQuoteNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1547}
)

// CSRNeedsQuoteVerification checks if QuoteValidation extension set in the
// given csr
func CSRNeedsQuoteVerification(csr *x509.CertificateRequest) bool {
	for _, val := range csr.Extensions {
		if val.Id.Equal(oidQuote) {
			return true
		}
	}
	return false
}

// ValidateCSRQuote validates the quote information embedded in the
// given certificate signing request. Returns if any error occur doing so.
//
// When this function returns with retry, means the quote verification is
// is in progress so, recall this method after sometime. Otherwise, the
// verification result is returned.
func ValidateCSRQuote(ctx context.Context, c client.Client, obj client.Object, csr *x509.CertificateRequest, signer string) (verified, retry bool, err error) {
	nsName := client.ObjectKey{Name: obj.GetName(), Namespace: obj.GetNamespace()}
	if nsName.Namespace == "" {
		nsName.Namespace = k8sutil.GetNamespace()
	}
	qa := &tcsapi.QuoteAttestation{}
	if err := c.Get(ctx, nsName, qa); err != nil && errors.IsNotFound(err) {
		// means no quoteattestation object, create new one
		quoteInfo, err := getQuoteAndPublicKeyFromCSR(csr.Extensions)
		if err != nil {
			return false, false, fmt.Errorf("incomplete information to verify quote from csr extensions: %v", err)
		}

		ownerRef := &metav1.OwnerReference{
			APIVersion: obj.GetObjectKind().GroupVersionKind().GroupVersion().String(),
			Kind:       obj.GetObjectKind().GroupVersionKind().Kind,
			Name:       obj.GetName(),
			UID:        obj.GetUID(),
		}
		if err := k8sutil.QuoteAttestationDeliver(ctx, c, nsName, tcsapi.RequestTypeQuoteAttestation, signer, quoteInfo, "", ownerRef, nil); err != nil {
			return false, true, fmt.Errorf("failed to initiate quote attestation: %v", err)
		}
		return false, true, nil
	} else if err != nil {
		return false, true, fmt.Errorf("failed to fetch existing QuoteAttestation object: %v", err)
	}

	status := qa.Status.GetCondition(tcsapi.ConditionReady)
	if status == nil || status.Status == v1.ConditionUnknown {
		// Still quote is verification not verified, retry later
		return false, true, nil
	}
	// Remove quote attestation object
	defer c.Delete(context.Background(), qa)
	return status.Status == v1.ConditionTrue, false, nil
}

func getQuoteAndPublicKeyFromCSR(extensions []pkix.Extension) (*keyprovider.QuoteInfo, error) {
	decodeExtensionValue := func(value []byte) ([]byte, error) {
		strValue := ""
		if _, err := asn1.Unmarshal(value, &strValue); err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(strValue)
	}
	var quoteInfo keyprovider.QuoteInfo
	for _, ext := range extensions {
		if ext.Id.Equal(oidQuote) {
			quote, err := decodeExtensionValue(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal SGX quote extension value: %v", err)
			}
			quoteInfo.Quote = quote
		} else if ext.Id.Equal(oidQuotePublicKey) {
			encPublickey, err := decodeExtensionValue(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal SGX quote extension value: %v", err)
			}
			key, err := sgxutils.ParseQuotePublickey(encPublickey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse SGX quote publickey value: %v", err)
			}
			quoteInfo.PublicKey = key
		} else if ext.Id.Equal(oidQuoteNonce) {
			nonce, err := decodeExtensionValue(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse SGX quote publickey value: %v", err)
			}
			quoteInfo.Nonce = nonce
		}
	}
	if quoteInfo.Quote == nil {
		return nil, fmt.Errorf("missing quote extension")
	}
	if quoteInfo.PublicKey == nil {
		return nil, fmt.Errorf("missing quote public key extension")
	}
	if quoteInfo.Nonce == nil {
		return nil, fmt.Errorf("missing quote nonce extension")
	}
	return &quoteInfo, nil
}

func GetQuoteVerifiedExtension(message string) (*pkix.Extension, error) {
	val := asn1.RawValue{
		Bytes: []byte(message),
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
	}
	bs, err := asn1.Marshal(val)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the raw values for SGX field: %v", err)
	}
	return &pkix.Extension{
		Id:       oidQuote,
		Critical: false,
		Value:    bs,
	}, nil
}
