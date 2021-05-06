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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/controllers"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/signer"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	testutils "github.com/intel/trusted-certificate-issuer/test/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("QuoteAttestaion controller", func() {
	const (
		testSigner    = "foo.bar.com/test-signer"
		unknownSigner = "foo.bar.com/unknown"
	)

	var fakeKeyProvider keyprovider.KeyProvider
	var qc *controllers.QuoteAttestationReconciler

	scheme := runtime.NewScheme()
	err := tcsapi.AddToScheme(scheme)
	Expect(err).ShouldNot(HaveOccurred(), "failed to add QA API to scheme")

	BeforeEach(func() {
		Expect(cfg).ShouldNot(BeNil(), "nil config")
		Expect(k8sClient).ShouldNot(BeNil())
		fakeKeyProvider = testutils.NewKeyProvider(map[string]*signer.Signer{
			testSigner: signer.NewSigner(testSigner),
		})
		qc = controllers.NewQuoteAttestationReconciler(k8sClient, fakeKeyProvider, nil)
	})

	AfterEach(func() {
		fakeKeyProvider = nil
		qc = nil
	})

	It("runs", func() {
		obj := newQuoteAttestation("qac-runs", "default", testSigner)
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      obj.Name,
				Namespace: obj.Namespace,
			},
		})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")
	})

	It("could retrieve the provisioned key and certificate", func() {
		// 1. Create QuoteAttestation object
		obj := newQuoteAttestation("qa-success", "default", testSigner)
		qaKey := types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		// 2. Prepre required secrets
		caKey, err := rsa.GenerateKey(rand.Reader, 3072)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create keypair")

		caCert, err := newCACertificate(caKey)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create ca certificate")

		// create secret with key and certificate
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-secret",
				Namespace: obj.Namespace,
			},
			Data: map[string][]byte{
				v1.TLSCertKey:       caCert,
				v1.TLSPrivateKeyKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(caKey))),
			},
		}
		err = k8sClient.Create(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create secret")
		defer k8sClient.Delete(context.TODO(), secret)

		// 3. Fetch and update the attestation status
		qa := &tcsapi.QuoteAttestation{}
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve quote attestation object")

		if qa.Status.Secrets == nil {
			qa.Status.Secrets = map[string]tcsapi.QuoteAttestationSecret{}
		}
		for _, signer := range qa.Spec.SignerNames {
			qa.Status.Secrets[signer] = tcsapi.QuoteAttestationSecret{
				SecretType: "KMRA",
				SecretName: secret.Name,
			}
		}

		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "")

		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 4. Ensure that reconciler catches the secrets
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected not requeue")

		// 5. Ensure the CA secrets are initialized with the key provider
		s, err := fakeKeyProvider.GetSignerForName(testSigner)
		Expect(err).ShouldNot(HaveOccurred(), "unexpected error while fetching certificate")
		Expect(s).ShouldNot(BeNil(), "unexpected error while fetching certificate")

		// 6. Ensure that the CR Ready condition set for status
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "Retrive CR")
		cond := qa.Status.GetCondition(tcsapi.ConditionReady)
		Expect(cond).ShouldNot(BeNil(), "Ready condition")
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionTrue))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))

		//7. Next reconcile should Remove the CR
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")

		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).Should(HaveOccurred(), "Retrive CR")
	})

	It("should detect unsupported secret type", func() {
		// 1. Create QuoteAttestation object
		obj := newQuoteAttestation("qa-success", "default", testSigner)
		qaKey := types.NamespacedName{Name: obj.Name, Namespace: obj.Namespace}
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		// 2. Prepre required secrets
		caKey, err := rsa.GenerateKey(rand.Reader, 3072)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create keypair")

		caCert, err := newCACertificate(caKey)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create ca certificate")

		// create secret with key and certificate
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-secret",
				Namespace: obj.Namespace,
			},
			Data: map[string][]byte{
				v1.TLSCertKey:       caCert,
				v1.TLSPrivateKeyKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(caKey))),
			},
		}
		err = k8sClient.Create(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create secret")
		defer k8sClient.Delete(context.TODO(), secret)

		// 3. Fetch and update the attestation status
		qa := &tcsapi.QuoteAttestation{}
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve quote attestation object")

		if qa.Status.Secrets == nil {
			qa.Status.Secrets = map[string]tcsapi.QuoteAttestationSecret{}
		}
		for _, signer := range qa.Spec.SignerNames {
			qa.Status.Secrets[signer] = tcsapi.QuoteAttestationSecret{
				SecretType: "FOOBAR",
				SecretName: secret.Name,
			}
		}

		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 4. Ensure that reconciler catches the secret type
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected requeue")

		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "read attestation object")
		cond := qa.Status.GetCondition(tcsapi.ConditionCASecretReady)
		By(fmt.Sprintf("Condition: %v", cond))
		Expect(cond).ShouldNot(BeNil())
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionFalse))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))
		Expect(cond.Message).Should(ContainSubstring("unsupported secret type"))
	})

	It("should detect attestation failure", func() {
		// 1. Create QuoteAttestation object
		obj := newQuoteAttestation("qa-failed", "default", testSigner)
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		qaKey := types.NamespacedName{
			Name:      obj.Name,
			Namespace: obj.Namespace,
		}

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		// 2. Retrieve QuoteAttestatin object from API server
		qa := &tcsapi.QuoteAttestation{}
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve quote attestation object")

		// 3. Update status with appropriate failure
		qa.Status.SetCondition(tcsapi.ConditionQuoteVerified, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, "SGX attestation failed")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 4. Ensure that the reconciler could recognize the failure
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")

		s, err := fakeKeyProvider.GetSignerForName(testSigner)
		Expect(err).ShouldNot(HaveOccurred(), "unexpected error")
		Expect(s).ShouldNot(BeNil())
		Expect(s.Error()).Should(HaveOccurred(), "expected an error")
	})

	It("should detect missing ca certificate", func() {
		// 1. Create QuoteAttestation object
		obj := newQuoteAttestation("qa-incomplete-status", "default", testSigner)
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		qaKey := types.NamespacedName{
			Name:      obj.Name,
			Namespace: obj.Namespace,
		}

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		// 2. Retrieve QuoteAttestatin object from API server
		qa := &tcsapi.QuoteAttestation{}
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve quote attestation object")

		// 2. Prepre required secrets with missing certificate
		caKey, err := rsa.GenerateKey(rand.Reader, 3072)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create keypair")

		// create secret with key and certificate
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-secret",
				Namespace: obj.Namespace,
			},
			Data: map[string][]byte{
				v1.TLSCertKey:       {},
				v1.TLSPrivateKeyKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(caKey))),
			},
		}
		err = k8sClient.Create(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create secret")
		defer k8sClient.Delete(context.TODO(), secret)

		qa.Status.Secrets = map[string]tcsapi.QuoteAttestationSecret{}
		for _, signer := range qa.Spec.SignerNames {
			qa.Status.Secrets[signer] = tcsapi.QuoteAttestationSecret{
				SecretType: "KMRA",
				SecretName: secret.Name,
			}
		}

		// 3. Update status with appropriate failure
		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA secrets ready")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 4. Ensure that the reconciler could recognize the failure
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")

		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to read atttestation object")
		cond := qa.Status.GetCondition(tcsapi.ConditionCASecretReady)
		Expect(cond).ShouldNot(BeNil())
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionFalse))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))
		Expect(cond.Message).Should(ContainSubstring("missing CA certificate"))
	})

	It("should detect missing ca key", func() {
		// 1. Create QuoteAttestation object
		obj := newQuoteAttestation("qa-incomplete-status", "default", testSigner)
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		qaKey := types.NamespacedName{
			Name:      obj.Name,
			Namespace: obj.Namespace,
		}

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		// 2. Retrieve QuoteAttestatin object from API server
		qa := &tcsapi.QuoteAttestation{}
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve quote attestation object")

		// 2. Prepre required secrets with missing certificate
		caKey, err := rsa.GenerateKey(rand.Reader, 3072)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create keypair")

		caCert, err := newCACertificate(caKey)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create ca certificate")

		// create secret with key and certificate
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-secret",
				Namespace: obj.Namespace,
			},
			Data: map[string][]byte{
				v1.TLSCertKey:       caCert,
				v1.TLSPrivateKeyKey: {},
			},
		}
		err = k8sClient.Create(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create secret")
		defer k8sClient.Delete(context.TODO(), secret)

		qa.Status.Secrets = map[string]tcsapi.QuoteAttestationSecret{}
		for _, signer := range qa.Spec.SignerNames {
			qa.Status.Secrets[signer] = tcsapi.QuoteAttestationSecret{
				SecretType: "KMRA",
				SecretName: secret.Name,
			}
		}

		// 3. Update status
		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA secrets ready")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 4. Ensure that the reconciler could recognize the failure
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "expected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to read quote attestation object")
		cond := qa.Status.GetCondition(tcsapi.ConditionCASecretReady)
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionFalse))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))
		Expect(cond.Message).Should(ContainSubstring("missing CA private key"))
	})

	It("should detect malformed data", func() {
		// 1. Create QuoteAttestation object
		obj := newQuoteAttestation("qa-malformed-secret", "default", testSigner)
		err = k8sClient.Create(context.TODO(), obj)
		Expect(err).ShouldNot(HaveOccurred(), "failed to crate quote attestation object")
		defer k8sClient.Delete(context.TODO(), obj)

		qaKey := types.NamespacedName{
			Name:      obj.Name,
			Namespace: obj.Namespace,
		}

		res, err := qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		// 2. Retrieve QuoteAttestatin object from API server
		qa := &tcsapi.QuoteAttestation{}
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to retrieve quote attestation object")

		// 2. Prepre required secrets with missing certificate
		caKey, err := rsa.GenerateKey(rand.Reader, 3072)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create keypair")

		caCert, err := newCACertificate(caKey)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create ca certificate")

		// create secret with key and certificate
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-secret",
				Namespace: obj.Namespace,
			},
			Data: map[string][]byte{
				v1.TLSCertKey: caCert,
				v1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: []byte("random bytes"),
				}),
			},
		}
		err = k8sClient.Create(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to create secret")
		defer k8sClient.Delete(context.TODO(), secret)

		qa.Status.Secrets = map[string]tcsapi.QuoteAttestationSecret{}
		for _, signer := range qa.Spec.SignerNames {
			qa.Status.Secrets[signer] = tcsapi.QuoteAttestationSecret{
				SecretType: "KMRA",
				SecretName: secret.Name,
			}
		}

		// 3. Update status with appropriate failure
		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA secrets ready")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 4. Ensure that the reconciler could recognize the failure
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
		Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile")

		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to read quote attestation object")
		cond := qa.Status.GetCondition(tcsapi.ConditionCASecretReady)
		Expect(cond).ShouldNot(BeNil())
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionFalse))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile)) // error text defined in test/utils/ca-provider.go
		Expect(cond.Message).Should(ContainSubstring("corrupted key data"))   // error text defined in test/utils/ca-provider.go

		err = k8sClient.Get(context.TODO(), client.ObjectKeyFromObject(secret), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed fetch secret")

		// 5. update the secret with right key and update the attestation object status
		secret.Data[v1.TLSPrivateKeyKey] = []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(caKey)))
		err = k8sClient.Update(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update secret")

		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA keys ready")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 5. Ensure that the reconciling should succeed
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected error")
		Expect(res.Requeue).Should(BeTrue(), "expected requeue")

		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to read quote attestation object")
		cond = qa.Status.GetCondition(tcsapi.ConditionReady)
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionTrue))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))

		s, err := fakeKeyProvider.GetSignerForName(testSigner)
		Expect(err).ShouldNot(HaveOccurred(), "get signer")
		s.SetPending(qaKey.Name)
		// 6. Pass corrupted Certificate
		err = k8sClient.Get(context.TODO(), client.ObjectKeyFromObject(secret), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed fetch secret")
		secret.Data[v1.TLSCertKey] = []byte("malformed data")
		err = k8sClient.Update(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update secret")
		// Reset the CR status
		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA keys ready")
		deleteCondition(&qa.Status, tcsapi.ConditionReady)
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update CR")

		By(fmt.Sprintf("Updated CR with conditions: %v", qa.Status.Conditions))

		// 7. Ensure that the reconciler detects the failure
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected error")
		Expect(res.Requeue).Should(BeTrue(), "expected requeue")
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to read quote attestation object")
		cond = qa.Status.GetCondition(tcsapi.ConditionCASecretReady)
		Expect(cond).ShouldNot(BeNil())
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionFalse))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))
		Expect(cond.Message).Should(ContainSubstring("corrupted certificate"))

		// 8. Update the secret with right certificate
		err = k8sClient.Get(context.TODO(), client.ObjectKeyFromObject(secret), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed fetch secret")
		secret.Data[v1.TLSCertKey] = caCert
		err = k8sClient.Update(context.TODO(), secret)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update secret")
		// Reset the CR status
		qa.Status.SetCondition(tcsapi.ConditionCASecretReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "CA keys ready")
		err = k8sClient.Status().Update(context.TODO(), qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to update attestation status")

		// 9. Ensure that the reconciling should succeed
		res, err = qc.Reconcile(context.TODO(), reconcile.Request{NamespacedName: qaKey})
		Expect(err).ShouldNot(HaveOccurred(), "unexpected error")
		Expect(res.Requeue).Should(BeTrue(), "expected requeue")
		err = k8sClient.Get(context.TODO(), qaKey, qa)
		Expect(err).ShouldNot(HaveOccurred(), "failed to read quote attestation object")
		cond = qa.Status.GetCondition(tcsapi.ConditionReady)
		Expect(cond).ShouldNot(BeNil())
		Expect(cond.Status).Should(BeEquivalentTo(v1.ConditionTrue))
		Expect(cond.Reason).Should(BeEquivalentTo(tcsapi.ReasonTCSReconcile))
	})
})

func newQuoteAttestation(name, namespace, signerName string) *tcsapi.QuoteAttestation {
	quote := []byte("Dummy Quote")
	pubkey := []byte("Quote public key")
	qa := &tcsapi.QuoteAttestation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: tcsapi.QuoteAttestationSpec{
			Quote:        quote,
			PublicKey:    pubkey,
			QuoteVersion: tcsapi.ECDSAQuoteVersion3,
			SignerNames:  []string{signerName},
			ServiceID:    "QA-Test",
		},
	}

	return qa
}

func newCACertificate(key crypto.Signer) ([]byte, error) {
	cert, err := testutils.NewCACertificate(key, time.Now(), 365*24*time.Hour, true)
	if err != nil {
		return nil, err
	}

	pemCert := tlsutil.EncodeCert(cert)

	return []byte(base64.StdEncoding.EncodeToString(pemCert)), nil
}

func deleteCondition(status *tcsapi.QuoteAttestationStatus, cond tcsapi.ConditionType) {
	for i, c := range status.Conditions {
		if c.Type == cond {
			status.Conditions = append(status.Conditions[:i], status.Conditions[i+1:]...)
			return
		}
	}
}
