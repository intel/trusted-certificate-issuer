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
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	selfca "github.com/intel/trusted-certificate-issuer/internal/self-ca"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	crtv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	RetryTimeout = 5 * time.Second
)

// CSRReconciler reconciles a CSR object
type CSRReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Log           logr.Logger
	KeyProvider   keyprovider.KeyProvider
	mutex         sync.Mutex
	fullCertChain bool
}

func NewCSRReconciler(c client.Client, scheme *runtime.Scheme, keyProvider keyprovider.KeyProvider, fullCertChain bool) *CSRReconciler {
	return &CSRReconciler{
		Log:           ctrl.Log.WithName("controllers").WithName("CSR"),
		Client:        c,
		Scheme:        scheme,
		KeyProvider:   keyProvider,
		fullCertChain: fullCertChain,
	}
}

//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/finalizers,verbs=update
//+kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,resourceNames=tcsissuer.tcs.intel.com/*;tcsclusterissuer.tcs.intel.com/*,verbs=sign

func (r *CSRReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r == nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("nil reconciler")
	}
	l := r.Log.WithValues("reconcile", req.NamespacedName)

	l.Info("CSR Reconcile")

	r.mutex.Lock()
	defer r.mutex.Unlock()

	retry := ctrl.Result{Requeue: true, RequeueAfter: RetryTimeout}

	csr := crtv1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: crtv1.SchemeGroupVersion.String(),
			Kind:       "CertificateSigningRequest",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil && !errors.IsNotFound(err) {
		l.V(1).Error(err, "Failed to fetch CSR object")
		return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, err
	}

	if !csr.DeletionTimestamp.IsZero() {
		l.Info("CSR has been deleted. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerRef := IssuerRefForSignerName(csr.Spec.SignerName)
	if issuerRef == nil {
		l.Info("CSR signer name does not match. Ignoring.", "signer-name", csr.Spec.SignerName)
		return ctrl.Result{}, nil
	}

	if csrHasCondition(&csr.Status, crtv1.CertificateDenied) {
		l.Info("CSR is denied, Ignoring.")
		return ctrl.Result{}, nil
	}

	if !csrHasCondition(&csr.Status, crtv1.CertificateApproved) {
		l.Info("CSR is not approved, Ignoring.")
		return ctrl.Result{}, nil
	}
	if len(csr.Status.Certificate) > 0 {
		l.Info("CSR has already been signed. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuer, err := GetIssuer(ctx, r.Client, r.Scheme, issuerRef)
	if err != nil {
		l.Info("Unknown issuer. Ignoring.", "error", err)
		return ctrl.Result{}, nil
	}

	_, issuerStatus, err := IssuerSpecAndStatus(issuer)
	if err != nil {
		l.Error(err, "Unrecognized issuer. Ignoring.")
		return ctrl.Result{}, err
	}

	l.Info("Issuer", "Status", issuerStatus)

	if c := issuerStatus.GetCondition(tcsapi.IssuerConditionReady); c == nil || c.Status == v1.ConditionFalse {
		l.Info("Issuer Not ready", "condition", c)
		return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, errIssuerNotReady
	}

	l.Info("Signing", "csr", req)
	signerName := SignerNameForIssuer(schema.GroupVersionKind{
		Kind:    issuerRef.Kind,
		Version: "v1alpha1",
		Group:   tcsapi.GroupName,
	}, issuer.GetName(), issuer.GetNamespace())
	s, err := r.KeyProvider.GetSignerForName(signerName)
	if err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, fmt.Errorf("failed to get signer for name '%s': %v", signerName, err)
	}

	ca, err := selfca.NewCA(s, s.Certificate())
	if err != nil {
		return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, fmt.Errorf("failed to prepare CA: %v", err)
	}
	keyUsage, extKeyUsage, err := k8sKeyUsagesToX509KeyUsages(csr.Spec.Usages)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("signing failed: %v", err)
	}

	cert, err := ca.Sign(csr.Spec.Request, keyUsage, extKeyUsage)
	if err != nil {
		return retry, fmt.Errorf("error auto signing csr: %v", err)
	}

	patch := client.MergeFrom(csr.DeepCopy())
	if r.fullCertChain {
		l.Info("Preparing full certificate chain")
		// NOTE(avalluri): This is a temporary solution to make it work with Istio v1.12,
		// Where it expects the full certChain along with the root certificate.
		// But according to https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2
		// self-signed root certificate should not include the certificat chain.
		certChain, err := encodeX509Chain([]*x509.Certificate{cert, s.Certificate()})
		if err != nil {
			return retry, fmt.Errorf("error preparing cert chain: %v", err)
		}
		csr.Status.Certificate = certChain
	} else {
		csr.Status.Certificate = tlsutil.EncodeCert(cert)
	}
	if err := r.Client.Status().Patch(ctx, &csr, patch); err != nil {
		return retry, fmt.Errorf("error patching CSR: %v", err)
	}
	l.Info("Signing done")
	//r.EventRecorder.Event(&csr, v1.EventTypeNormal, "Signed", "The CSR has been signed")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CSRReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&crtv1.CertificateSigningRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: crtv1.SchemeGroupVersion.String(),
				Kind:       "CertificateSigningRequest",
			},
		}).
		Complete(r)
}

// isCSRApproved checks if the given Kubernetes certificate signing request
// has been approved by the cluster admin
func isCSRApproved(csrStatus *crtv1.CertificateSigningRequestStatus) bool {
	approved := false
	for _, c := range csrStatus.Conditions {
		if c.Type == crtv1.CertificateApproved {
			approved = true
		}
		if c.Type == crtv1.CertificateDenied {
			return false
		}
	}

	return approved
}

func csrHasCondition(csrStatus *crtv1.CertificateSigningRequestStatus,
	condition crtv1.RequestConditionType) bool {

	for _, c := range csrStatus.Conditions {
		if c.Type == condition {
			return true
		}
	}

	return false
}

func k8sKeyUsagesToX509KeyUsages(usages []crtv1.KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	keyUsageDict := map[crtv1.KeyUsage]x509.KeyUsage{
		crtv1.UsageSigning:           x509.KeyUsageDigitalSignature,
		crtv1.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
		crtv1.UsageContentCommitment: x509.KeyUsageContentCommitment,
		crtv1.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
		crtv1.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
		crtv1.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
		crtv1.UsageCertSign:          x509.KeyUsageCertSign,
		crtv1.UsageCRLSign:           x509.KeyUsageCRLSign,
		crtv1.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
		crtv1.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
	}

	extKeyUsageDict := map[crtv1.KeyUsage]x509.ExtKeyUsage{
		crtv1.UsageAny:             x509.ExtKeyUsageAny,
		crtv1.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
		crtv1.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
		crtv1.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
		crtv1.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
		crtv1.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
		crtv1.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
		crtv1.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
		crtv1.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
		crtv1.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
		crtv1.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
		crtv1.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		crtv1.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
	}

	keyUsage := x509.KeyUsage(0)
	extUsage := []x509.ExtKeyUsage{}
	unknownUsages := []string{}

	for _, usage := range usages {
		if v, ok := keyUsageDict[usage]; ok {
			keyUsage |= v
		} else if v, ok := extKeyUsageDict[usage]; ok {
			extUsage = append(extUsage, v)
		} else {
			unknownUsages = append(unknownUsages, string(usage))
		}
	}

	if len(unknownUsages) != 0 {
		return keyUsage, extUsage, fmt.Errorf("unrecognized key usage: %v", unknownUsages)
	}

	return keyUsage, extUsage, nil
}

func encodeX509Chain(certs []*x509.Certificate) ([]byte, error) {
	caPem := bytes.NewBuffer([]byte{})
	//caPem := []byte{}
	for _, cert := range certs {
		caPem.Write(tlsutil.EncodeCert(cert)[:])
	}

	return caPem.Bytes(), nil
}
