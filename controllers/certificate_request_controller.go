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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	selfca "github.com/intel/trusted-certificate-issuer/internal/self-ca"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	cmutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmpki "github.com/jetstack/cert-manager/pkg/util/pki"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
)

// CSRReconciler reconciles a CSR object
type CertificateRequestReconciler struct {
	client.Client
	Log         logr.Logger
	Scheme      *runtime.Scheme
	KeyProvider keyprovider.KeyProvider
	caProviders map[string]*selfca.CA
	mutex       sync.Mutex
}

func NewCertificateRequestReconciler(c client.Client, keyProvider keyprovider.KeyProvider) *CertificateRequestReconciler {
	return &CertificateRequestReconciler{
		Log:         ctrl.Log.WithName("controllers").WithName("cr"),
		Client:      c,
		KeyProvider: keyProvider,
		caProviders: map[string]*selfca.CA{},
	}
}

//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/finalizers,verbs=update

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	if r == nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("nil reconciler")
	}
	l := r.Log.WithValues("req", req.NamespacedName)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	cr := &cmapi.CertificateRequest{}

	if err := r.Get(ctx, req.NamespacedName, cr); err != nil && !apierrors.IsNotFound(err) {
		l.V(1).Error(err, "Failed to fetch CSR object")
		return ctrl.Result{Requeue: true, RequeueAfter: time.Minute}, err
	}

	l.Info("Reconcile")

	patch := client.MergeFrom(cr.DeepCopy())

	// We now have a cr that belongs to us so we are responsible
	// for updating its Ready condition.
	setReadyCondition := func(status cmmeta.ConditionStatus, reason, message string) {
		cmutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, message)
	}

	ignore := false
	defer func() {
		if ignore {
			return
		}
		if err != nil {
			setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
			// Reset err to nil, otherwise the controller will
			// retry the request assuming that reconcile failure.
			err = nil
		}
		l.Info("Updating CR status")
		if updateErr := r.Client.Status().Patch(ctx, cr, patch); updateErr != nil {
			err = fmt.Errorf("error patching the CertificateRequest status: %v", updateErr)
		}
	}()

	// Reconciling cr, Original code from:
	// https://github.com/cert-manager/sample-external-issuer/blob/main/internal/controllers/certificaterequest_controller.go
	switch {
	case !cr.DeletionTimestamp.IsZero():
		ignore = true
	case cr.Spec.IssuerRef.Group != tcsapi.GroupName:
		ignore = true
	case cmutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}):
		ignore = true
		l.Info("cr is Ready. Ignoring.")
	case cmutil.CertificateRequestHasCondition(cr, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}):
		ignore = true
		l.Info("cr is has denied. Ignoring.")
	case cmutil.CertificateRequestIsDenied(cr):
		l.Info("cr has been denied. Marking as failed.")

		if cr.Status.FailureTime == nil {
			nowTime := metav1.Now()
			cr.Status.FailureTime = &nowTime
		}

		message := "The cr was denied by an approval controller"
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
		return ctrl.Result{}, nil
	case !cmutil.CertificateRequestIsApproved(cr):
		ignore = true
		l.Info("cr has not been approved yet. Ignoring.")
		return ctrl.Result{}, nil
	default:
		// Add a Ready condition if one does not already exist
		if ready := cmutil.GetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady); ready == nil {
			l.Info("Initializing Ready condition")
			setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Initializing")
			return ctrl.Result{}, nil
		}

		issuerRef := &IssuerRef{
			NamespacedName: types.NamespacedName{
				Name:      cr.Spec.IssuerRef.Name,
				Namespace: cr.Namespace,
			},
			Kind: cr.Spec.IssuerRef.Kind,
		}

		issuer, err := GetIssuer(ctx, r.Client, r.Scheme, issuerRef)
		if err != nil {
			l.Error(err, "Unable to get the Issuer. Ignoring.")
			return ctrl.Result{}, err
		}

		_, issuerStatus, err := IssuerSpecAndStatus(issuer)
		if err != nil {
			l.Error(err, "Unable to get the IssuerStatus. Ignoring.")
			return ctrl.Result{}, err
		}

		c := issuerStatus.GetCondition(tcsapi.IssuerConditionReady)
		if c == nil || c.Status == v1.ConditionFalse {
			return ctrl.Result{}, errIssuerNotReady
		}

		signerName := SignerNameForIssuer(issuer.GetObjectKind().GroupVersionKind(), issuer.GetName(), issuer.GetNamespace())
		s, err := r.KeyProvider.GetSignerForName(signerName)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to get signer for name '%s': %v", signerName, err)
		}

		ca, err := selfca.NewCA(s, s.Certificate())
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to prepare CA: %v", err)
		}

		keyUsage, extKeyUsage, err := cmpki.BuildKeyUsages(cr.Spec.Usages, cr.Spec.IsCA)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("key usage error> %v", err)
		}

		l.Info("Signing ...")
		cert, err := ca.Sign(cr.Spec.Request, keyUsage, extKeyUsage)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to sign CertificateRequest: %v", err)
		}

		cr.Status.Certificate = tlsutil.EncodeCert(cert)
		cr.Status.CA = ca.EncodedCertificate()
		setReadyCondition(cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Signed")
		l.Info("Signing done")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: cmapi.SchemeGroupVersion.String(),
				Kind:       "CertificateRequest",
			},
		}).
		Complete(r)
}
