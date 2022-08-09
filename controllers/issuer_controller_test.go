/*
Copyright 2022 Intel(R).

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
	"encoding/base64"
	"os"
	"time"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/controllers"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	testutils "github.com/intel/trusted-certificate-issuer/test/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Issuer controller", func() {
	keyProviderConfig := testutils.Config{
		AddSignerError: testutils.SignerError{
			Name:       "add-failure",
			ErrMessage: "internal error to initialize signer secrets",
		},
		ProvisionSignerError: testutils.SignerError{
			Name:       "provision-failure",
			ErrMessage: "internal error to save signer secrets",
		},
	}
	var fakeKeyProvider keyprovider.KeyProvider

	os.Setenv("WATCH_NAMESPACE", testIssuerNS)
	newIssuer := func(isCluster bool, objMeta types.NamespacedName, secretName string, selfSign bool) client.Object {
		meta := metav1.ObjectMeta{
			Name:      objMeta.Name,
			Namespace: objMeta.Namespace,
		}
		spec := tcsapi.TCSIssuerSpec{
			SecretName:          secretName,
			SelfSignCertificate: &selfSign,
		}
		if isCluster {
			return &tcsapi.TCSClusterIssuer{
				TypeMeta: metav1.TypeMeta{
					APIVersion: tcsapi.GroupVersion.String(),
					Kind:       "TCSClusterIssuer",
				},
				ObjectMeta: meta,
				Spec:       spec,
			}
		}

		return &tcsapi.TCSIssuer{
			TypeMeta: metav1.TypeMeta{
				APIVersion: tcsapi.GroupVersion.String(),
				Kind:       "TCSIssuer",
			},
			ObjectMeta: meta,
			Spec:       spec,
		}
	}

	validateIssuerStatus := func(objName types.NamespacedName, issuer client.Object, expectedState v1.ConditionStatus, message string) {
		err := k8sClient.Get(context.TODO(), objName, issuer)
		ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "failed to get issuer")
		_, status, err := controllers.IssuerSpecAndStatus(issuer)
		ExpectWithOffset(1, err).ShouldNot(HaveOccurred())
		ready := status.GetCondition(tcsapi.IssuerConditionReady)
		ExpectWithOffset(1, ready).ShouldNot(BeNil(), "expected ready condition")
		ExpectWithOffset(1, ready.Status).Should(BeEquivalentTo(expectedState), "unexpected status condition")
		ExpectWithOffset(1, ready.Message).Should(HaveSuffix(message), "unexpected status condition")
	}

	validateIssuerSecret := func(key types.NamespacedName) {
		secret := &v1.Secret{}
		err := k8sClient.Get(context.TODO(), key, secret)
		ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "failed to get issuer secret: %v", key)
		ExpectWithOffset(1, secret.Data[v1.TLSCertKey]).ShouldNot(BeEmpty(), "expected certificate in the secret")
		ExpectWithOffset(1, secret.Data[v1.TLSPrivateKeyKey]).Should(BeEmpty(), "expected no private eky in the secret")
	}

	validateSignerSecrets := func(issuerGVK schema.GroupVersionKind, objName types.NamespacedName) {
		signerName := controllers.SignerNameForIssuer(issuerGVK, objName.Name, objName.Namespace)
		s, err := fakeKeyProvider.GetSignerForName(signerName)
		ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "error fetching the signer: %v", signerName)
		ExpectWithOffset(1, s).ShouldNot(BeNil(), "empty signer")

		ExpectWithOffset(1, s.Ready()).Should(BeTrue(), "expected signer should be ready")
		ExpectWithOffset(1, s.Certificate()).ShouldNot(BeNil(), "expected a valid certificate")
		ExpectWithOffset(1, s.Signer).ShouldNot(BeNil(), "expected a valid crypto signer")
	}

	BeforeEach(func() {
		Expect(cfg).ShouldNot(BeNil(), "nil config")
		Expect(k8sClient).ShouldNot(BeNil())
		fakeKeyProvider = testutils.NewKeyProvider(keyProviderConfig)
	})

	AfterEach(func() {
		fakeKeyProvider = nil
	})

	var ic *controllers.IssuerReconciler = nil
	for _, kind := range []string{"TCSClusterIssuer", "TCSIssuer"} {
		kind := kind
		isCluster := true
		issuerGVK := schema.GroupVersionKind{}
		objName := types.NamespacedName{
			Namespace: testIssuerNS, // TCS Pod Namespace
		}
		Context(kind, func() {
			BeforeEach(func() {
				ic = &controllers.IssuerReconciler{
					Client:      k8sClient,
					Log:         ctrl.Log.WithName("controllers").WithName("test-issuer"),
					Kind:        kind,
					Scheme:      scheme,
					KeyProvider: fakeKeyProvider,
				}
				if kind == "TCSIssuer" {
					objName.Namespace = "default"
					isCluster = false
				}
				issuerGVK = schema.GroupVersionKind{
					Group:   tcsapi.GroupName,
					Version: tcsapi.GroupVersion.Version,
					Kind:    ic.Kind,
				}
			})
			It("shall provision issuer with self-signed certificate", func() {
				objName.Name = "self-signed"
				issuer := newIssuer(isCluster, objName, "ca-secret", true)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionTrue, "Success")

				validateIssuerSecret(types.NamespacedName{Name: "ca-secret", Namespace: objName.Namespace})
				validateSignerSecrets(issuerGVK, objName)
			})

			It("shall detect Keyprovider.AddSigner() failure", func() {
				objName.Name = keyProviderConfig.AddSignerError.Name
				issuer := newIssuer(isCluster, objName, "ca-secret", true)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, keyProviderConfig.AddSignerError.ErrMessage)
			})

			It("shall provision issuer key using quote attestation", func() {
				objName.Name = "key-provision"
				issuer := newIssuer(isCluster, objName, "ca-secret", false)
				err := k8sClient.Create(context.TODO(), issuer, &client.CreateOptions{
					Raw: &metav1.CreateOptions{
						FieldValidation: metav1.FieldValidationStrict,
					},
				})
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				err = k8sClient.Get(context.TODO(), objName, issuer)
				Expect(err).ShouldNot(HaveOccurred(), "fetch issuer object")

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Initiated key provisioning using QuoteAttestation")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Waiting for key provisioning")

				qa := &tcsapi.QuoteAttestation{}
				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).ShouldNot(HaveOccurred(), "retrieve issuer's QuoteAttestation object")

				// Update QuoteAttestation with CA key and certificate
				key, err := rsa.GenerateKey(rand.Reader, 3072)
				Expect(err).ShouldNot(HaveOccurred(), "create CA key")
				cert, err := testutils.NewCACertificate(key, time.Now(), time.Hour, true)
				Expect(err).ShouldNot(HaveOccurred(), "create CA certificate")

				qaSecret := &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      qa.Spec.SecretName,
						Namespace: qa.Namespace,
					},
					Data: map[string][]byte{
						// this supposed to be an encrypted key
						v1.TLSPrivateKeyKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(key))),
						v1.TLSCertKey:       []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeCert(cert))),
					},
				}
				err = k8sClient.Create(context.TODO(), qaSecret)
				Expect(err).ShouldNot(HaveOccurred(), "create CA secret")
				qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "Quote attestation success")
				err = k8sClient.Status().Update(context.TODO(), qa)
				Expect(err).ShouldNot(HaveOccurred(), "Update QA status")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionTrue, "Success")
				validateIssuerSecret(types.NamespacedName{Name: "ca-secret", Namespace: objName.Namespace})
				validateSignerSecrets(issuerGVK, objName)

				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).Should(HaveOccurred(), "check if QuoteAttestation object gets deleted")
			})

			It("shall handle quote attestation failure", func() {
				objName.Name = "failed-attestation"
				issuer := newIssuer(isCluster, objName, "ca-secret", false)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				err = k8sClient.Get(context.TODO(), objName, issuer)
				Expect(err).ShouldNot(HaveOccurred(), "fetch issuer object")

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Initiated key provisioning using QuoteAttestation")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Waiting for key provisioning")

				qa := &tcsapi.QuoteAttestation{}
				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).ShouldNot(HaveOccurred(), "retrieve issuer's QuoteAttestation object")

				qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionFalse, tcsapi.ReasonControllerReconcile, "invalid quote")
				err = k8sClient.Status().Update(context.TODO(), qa)
				Expect(err).ShouldNot(HaveOccurred(), "Update QA status")
				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "invalid quote")
			})

			It("shall detect missing attestation secret", func() {
				objName.Name = "failed-attestation"
				issuer := newIssuer(isCluster, objName, "ca-secret", false)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				err = k8sClient.Get(context.TODO(), objName, issuer)
				Expect(err).ShouldNot(HaveOccurred(), "fetch issuer object")

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Initiated key provisioning using QuoteAttestation")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Waiting for key provisioning")

				qa := &tcsapi.QuoteAttestation{}
				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).ShouldNot(HaveOccurred(), "retrieve issuer's QuoteAttestation object")

				// Update attestation success status without preparing the encrypted secret
				qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "Quote attestation success")
				err = k8sClient.Status().Update(context.TODO(), qa)
				Expect(err).ShouldNot(HaveOccurred(), "Update QA status")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "not found")
			})

			It("shall detect incomplete attestation secret: certificate", func() {
				objName.Name = "failed-attestation"
				issuer := newIssuer(isCluster, objName, "ca-secret", false)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				err = k8sClient.Get(context.TODO(), objName, issuer)
				Expect(err).ShouldNot(HaveOccurred(), "fetch issuer object")

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Initiated key provisioning using QuoteAttestation")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Waiting for key provisioning")

				// Update QA object with incomplete secret
				qa := &tcsapi.QuoteAttestation{}
				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).ShouldNot(HaveOccurred(), "retrieve issuer's QuoteAttestation object")

				key, err := rsa.GenerateKey(rand.Reader, 3072)
				Expect(err).ShouldNot(HaveOccurred(), "create CA key")

				qaSecret := &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      qa.Spec.SecretName,
						Namespace: qa.Namespace,
					},
					Data: map[string][]byte{
						// this supposed to be encrypted key
						v1.TLSPrivateKeyKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(key))),
					},
				}
				err = k8sClient.Create(context.TODO(), qaSecret)
				Expect(err).ShouldNot(HaveOccurred(), "create CA secret")
				defer k8sClient.Delete(context.TODO(), qaSecret)
				qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "Quote attestation success")
				err = k8sClient.Status().Update(context.TODO(), qa)
				Expect(err).ShouldNot(HaveOccurred(), "Update QA status")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "missing CA certificate")
			})

			It("shall detect incomplete attestation secret: privatekey", func() {
				objName.Name = "failed-attestation"
				issuer := newIssuer(isCluster, objName, "ca-secret", false)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				err = k8sClient.Get(context.TODO(), objName, issuer)
				Expect(err).ShouldNot(HaveOccurred(), "fetch issuer object")

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Initiated key provisioning using QuoteAttestation")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Waiting for key provisioning")

				// Update QA object with incomplete secret
				qa := &tcsapi.QuoteAttestation{}
				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).ShouldNot(HaveOccurred(), "retrieve issuer's QuoteAttestation object")

				key, err := rsa.GenerateKey(rand.Reader, 3072)
				Expect(err).ShouldNot(HaveOccurred(), "create CA key")
				cert, err := testutils.NewCACertificate(key, time.Now(), time.Hour, true)
				Expect(err).ShouldNot(HaveOccurred(), "create CA certificate")
				qaSecret := &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      qa.Spec.SecretName,
						Namespace: qa.Namespace,
					},
					Data: map[string][]byte{
						// this supposed to be encrypted key
						v1.TLSCertKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeCert(cert))),
					},
				}
				err = k8sClient.Create(context.TODO(), qaSecret)
				Expect(err).ShouldNot(HaveOccurred(), "create CA secret")
				defer k8sClient.Delete(context.TODO(), qaSecret)
				qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "Quote attestation success")
				err = k8sClient.Status().Update(context.TODO(), qa)
				Expect(err).ShouldNot(HaveOccurred(), "Update QA status")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "missing CA private key")
			})

			It("shall detect Keyprovider.ProvisionSigner() failure", func() {
				objName.Name = keyProviderConfig.ProvisionSignerError.Name
				issuer := newIssuer(isCluster, objName, "ca-secret", false)
				err := k8sClient.Create(context.TODO(), issuer)
				Expect(err).ShouldNot(HaveOccurred(), "failed to crate issuer object")
				defer k8sClient.Delete(context.TODO(), issuer)

				res, err := ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "expected retry reconcile on fist seen")
				validateIssuerStatus(objName, issuer, v1.ConditionUnknown, "First seen")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Initiated key provisioning using QuoteAttestation")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeTrue(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, "Waiting for key provisioning")

				qa := &tcsapi.QuoteAttestation{}
				err = k8sClient.Get(context.TODO(), objName, qa)
				Expect(err).ShouldNot(HaveOccurred(), "retrieve issuer's QuoteAttestation object")

				// Update QuoteAttestation with CA key and certificate
				key, err := rsa.GenerateKey(rand.Reader, 3072)
				Expect(err).ShouldNot(HaveOccurred(), "create CA key")
				cert, err := testutils.NewCACertificate(key, time.Now(), time.Hour, true)
				Expect(err).ShouldNot(HaveOccurred(), "create CA certificate")

				qaSecret := &v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      qa.Spec.SecretName,
						Namespace: qa.Namespace,
					},
					Data: map[string][]byte{
						v1.TLSPrivateKeyKey: []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeKey(key))),
						v1.TLSCertKey:       []byte(base64.StdEncoding.EncodeToString(tlsutil.EncodeCert(cert))),
					},
				}
				err = k8sClient.Create(context.TODO(), qaSecret)
				Expect(err).ShouldNot(HaveOccurred(), "create CA secret")
				qa.Status.SetCondition(tcsapi.ConditionReady, v1.ConditionTrue, tcsapi.ReasonControllerReconcile, "Quote attestation success")
				err = k8sClient.Status().Update(context.TODO(), qa)
				Expect(err).ShouldNot(HaveOccurred(), "Update QA status")

				res, err = ic.Reconcile(context.TODO(), reconcile.Request{NamespacedName: objName})
				Expect(err).ShouldNot(HaveOccurred(), "unexpected reconcile error")
				Expect(res.Requeue).Should(BeFalse(), "unexpected retry reconcile")
				validateIssuerStatus(objName, issuer, v1.ConditionFalse, keyProviderConfig.ProvisionSignerError.ErrMessage)
			})
		})
	}
})
