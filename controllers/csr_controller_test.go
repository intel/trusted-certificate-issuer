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

package controllers_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/controllers"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/signer"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	testutils "github.com/intel/trusted-certificate-issuer/test/utils"
	csrv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSR controller", func() {
	const (
		testSigner    = "tcsissuer.tcs.intel.com/default.test-signer"
		unknownSigner = "foo.bar.com/unknown"
	)

	request := newCertificateRequest(nil, "test-service")
	type testCase struct {
		provisionCA   bool
		csr           *csrv1.CertificateSigningRequest
		isApproved    bool
		isSignerReady bool

		expectedRequeue     bool
		expectedError       error
		validateCertificate bool
	}

	tests := map[string]testCase{
		"ignore request for unknown signer": {
			csr:             newCSR("unknown-signer-csr", unknownSigner, request, "", nil),
			expectedRequeue: false,
		},
		"ignore unapproved request": {
			csr:             newCSR("pending-csr", testSigner, request, "", nil),
			expectedRequeue: false,
		},
		"ignore denied request": {
			csr:             newCSR("denied-csr", testSigner, request, csrv1.CertificateDenied, nil),
			expectedRequeue: false,
		},
		"shall return appropriate error when signer not ready": {
			csr:             newCSR("signer-ready-csr", testSigner, request, csrv1.CertificateApproved, nil),
			isApproved:      true,
			isSignerReady:   false,
			expectedRequeue: true,
			expectedError:   fmt.Errorf("issuer is not ready"),
		},
		"should able to sign certificate": {
			provisionCA:         true,
			csr:                 newCSR("valid-csr", testSigner, request, csrv1.CertificateApproved, []csrv1.KeyUsage{csrv1.UsageCodeSigning}),
			isApproved:          true,
			isSignerReady:       true,
			expectedRequeue:     false,
			validateCertificate: true,
		},
	}

	var fakeKeyProvider keyprovider.KeyProvider
	var controller *controllers.CSRReconciler
	knownSigners := []string{testSigner}

	BeforeEach(func() {
		Expect(cfg).ShouldNot(BeNil())
		Expect(k8sClient).ShouldNot(BeNil())

		signers := map[string]*signer.Signer{}
		for _, name := range knownSigners {
			signers[name] = signer.NewSigner(name)
		}

		fakeKeyProvider = testutils.NewKeyProvider(signers)

		controller = controllers.NewCSRReconciler(k8sClient, scheme, fakeKeyProvider, false)
	})

	AfterEach(func() {
		fakeKeyProvider = nil
		controller = nil
		for _, name := range knownSigners {
			issuer := newIssuer(name)
			err := k8sClient.Delete(context.TODO(), issuer)
			Expect(err).ShouldNot(HaveOccurred(), "failed to delete issuer")
		}
	})

	for name, tc := range tests {
		name := name
		tc := tc

		It(name, func() {

			for _, name := range knownSigners {
				issuer := newIssuer(name)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to create issuer")

				if tc.isSignerReady {
					err = k8sClient.Get(context.TODO(), client.ObjectKeyFromObject(issuer), issuer)
					Expect(err).ShouldNot(HaveOccurred(), "failed to get issuer")
					_, status, _ := controllers.IssuerSpecAndStatus(issuer)
					status.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionTrue, "Manual Update", "Updated by unit test")
					err = k8sClient.Status().Update(context.TODO(), issuer)
					Expect(err).ShouldNot(HaveOccurred(), "failed to update issuer status")
				}
			}
			if tc.provisionCA {
				key, err := rsa.GenerateKey(rand.Reader, 3072)
				Expect(err).ShouldNot(HaveOccurred(), "failed to create keypair")

				cert, err := testutils.NewCACertificate(key, time.Now(), 365*24*time.Hour, true)
				Expect(err).ShouldNot(HaveOccurred(), "failed to create ca certificate")

				_, err = fakeKeyProvider.ProvisionSigner(testSigner, tlsutil.EncodeKey(key), cert)
				Expect(err).ShouldNot(HaveOccurred(), "failed to provision key")
			}

			err := k8sClient.Create(context.TODO(), tc.csr)
			Expect(err).ShouldNot(HaveOccurred(), "failed to create CSR object")
			defer k8sClient.Delete(context.TODO(), tc.csr)

			key := types.NamespacedName{
				Name:      tc.csr.GetName(),
				Namespace: tc.csr.GetNamespace(),
			}

			if tc.isApproved {
				csr := &csrv1.CertificateSigningRequest{}
				err = k8sClient.Get(context.TODO(), client.ObjectKeyFromObject(tc.csr), csr)
				Expect(err).ShouldNot(HaveOccurred(), "failed to get csr")

				csr.Status.Conditions = append(csr.Status.Conditions, csrv1.CertificateSigningRequestCondition{
					Type:           csrv1.CertificateApproved,
					Status:         corev1.ConditionTrue,
					Reason:         "Test Approval",
					Message:        "This CSR was approved by unit tester",
					LastUpdateTime: metav1.Now(),
				})

				// Get CSR client (controller-runtime client does not support CSR approving)
				cs, err := kubernetes.NewForConfig(cfg)
				Expect(err).ShouldNot(HaveOccurred(), "failed to get client set")
				Expect(cs).ShouldNot(BeNil(), "nil client set")
				// Approve CSR
				_, err = cs.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.TODO(), csr.GetName(), csr, metav1.UpdateOptions{})
				Expect(err).ShouldNot(HaveOccurred(), "failed to update csr approval")
			}

			result, err := controller.Reconcile(context.TODO(), ctrl.Request{NamespacedName: key})
			if tc.expectedError == nil {
				Expect(err).ShouldNot(HaveOccurred(), "unexpected error")
			} else {
				Expect(err).Should(HaveOccurred(), "expected an error")
				Expect(err.Error()).Should(ContainSubstring(tc.expectedError.Error()))
			}
			Expect(result.Requeue).Should(BeEquivalentTo(tc.expectedRequeue), "Unexpected result")

			if tc.validateCertificate {
				csr := csrv1.CertificateSigningRequest{}

				err := k8sClient.Get(context.TODO(), key, &csr)
				Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve CSR")

				Expect(csr.Status.Certificate).ShouldNot(BeNil(), "unexpected nil certificate")
				crt, err := tlsutil.DecodeCert(csr.Status.Certificate)
				Expect(err).ShouldNot(HaveOccurred(), "failed parse signed certificate")

				s, err := fakeKeyProvider.GetSignerForName(testSigner)
				Expect(err).ShouldNot(HaveOccurred(), "failed to get CA signer")

				Expect(crt.Issuer).Should(BeEquivalentTo(s.Certificate().Issuer), "unexpected certificate issuer")
			}
		})
	}
})

func newCSR(name, signerName string, request []byte, condition csrv1.RequestConditionType, usages []csrv1.KeyUsage) *csrv1.CertificateSigningRequest {
	if usages == nil {
		usages = []csrv1.KeyUsage{csrv1.UsageAny}
	}
	csr := &csrv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: csrv1.CertificateSigningRequestSpec{
			Request:    request,
			SignerName: signerName,
			Usages:     usages,
		},
	}

	return csr
}

func newCertificateRequest(key *rsa.PrivateKey, cn string) []byte {
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 1024)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create private key")
	}

	subj := pkix.Name{
		CommonName:         cn,
		Organization:       []string{"Test Ltd"},
		OrganizationalUnit: []string{"Trusted Certificate Service"},
	}

	csr, err := testutils.NewCertificateRequest(key, subj)
	Expect(err).ShouldNot(HaveOccurred(), "create certificate request")

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}

func newIssuer(signerName string) client.Object {
	ref := controllers.IssuerRefForSignerName(signerName)
	Expect(ref).ShouldNot(BeNil(), "invalid signer name")

	typeMeta := metav1.TypeMeta{
		Kind:       ref.Kind,
		APIVersion: "tcs.intel.com/v1alpha1",
	}
	metaData := metav1.ObjectMeta{
		Name:      ref.Name,
		Namespace: ref.Namespace,
	}

	switch ref.Kind {
	case "TCSClusterIssuer":
		return &tcsapi.TCSClusterIssuer{
			TypeMeta:   typeMeta,
			ObjectMeta: metaData,
		}
	case "TCSIssuer":
		return &tcsapi.TCSIssuer{
			TypeMeta:   typeMeta,
			ObjectMeta: metaData,
		}
	}
	Expect(fmt.Errorf("Unexpected kind: %s", ref.Kind)).ShouldNot(HaveOccurred())

	return nil
}
