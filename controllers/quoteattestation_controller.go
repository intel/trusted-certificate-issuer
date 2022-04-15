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
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/intel/trusted-certificate-issuer/internal/k8sutil"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v1alpha1 "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
)

const (
	// secret type used with KMRA
	KMRABased = "KMRA"
)

// QuoteAttestationReconciler reconciles a QuoteAttestation object
type QuoteAttestationReconciler struct {
	client.Client
	Log            logr.Logger
	KeyProvider    keyprovider.KeyProvider
	ExportCASecret bool
	Done           func()
	isDone         bool
	doneMutex      sync.Mutex
}

func NewQuoteAttestationReconciler(
	c client.Client,
	keyProvider keyprovider.KeyProvider,
	doneFunc func()) *QuoteAttestationReconciler {
	return &QuoteAttestationReconciler{
		Client:      c,
		KeyProvider: keyProvider,
		Done:        doneFunc,
		Log:         ctrl.Log.WithName("controllers").WithName("QuoteAttestation"),
	}
}

func (r *QuoteAttestationReconciler) done() {
	if r == nil || r.Done == nil {
		return
	}
	r.doneMutex.Lock()
	defer r.doneMutex.Unlock()
	if !r.isDone {
		r.Done()
		r.isDone = true
	}
}

func (r *QuoteAttestationReconciler) loadSecret(ctx context.Context, signerName, secretName, namespace string) error {
	// Check if already provisioned in earlier reconciling
	s, err := r.KeyProvider.GetSignerForName(signerName)
	if err == keyprovider.ErrNotFound {
		r.Log.V(3).Info("ignoring key provisioning for Unknown", "signer", signerName)
		return nil
	}

	if s.Ready() {
		r.Log.V(3).Info("ignoring key provisioning as CA is already in ready state", "signer", signerName)
		return nil
	}

	secret := &corev1.Secret{}
	key := client.ObjectKey{Name: secretName, Namespace: namespace}

	if err := r.Get(ctx, key, secret); err != nil {
		r.Log.Error(err, "Failed to get secret", "secret", secret, "signer", signerName)
		return err
	}

	wrappedKey, ok := secret.Data[v1.TLSPrivateKeyKey]
	if !ok || len(wrappedKey) == 0 {
		return fmt.Errorf("invalid secret: missing CA private key")
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(string(wrappedKey))
	if err != nil {
		return fmt.Errorf("corrupted key data: %v", err)
	}

	encCert, ok := secret.Data[v1.TLSCertKey]
	if !ok || len(encCert) == 0 {
		return fmt.Errorf("invalid secret: missing CA certificate")
	}

	pemCert, err := base64.StdEncoding.DecodeString(string(encCert))
	if err != nil {
		return fmt.Errorf("corrupted certificate: %v", err)
	}

	cert, err := tlsutil.DecodeCert(pemCert)
	if err != nil {
		return fmt.Errorf("corrupted certificate: %v", err)
	}

	if _, err = r.KeyProvider.ProvisionSigner(signerName, encryptedKey, cert); err != nil {
		r.Log.Error(err, "Failed to provision key to enclave")
		return err
	}
	return nil
}

//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations/finalizers,verbs=update
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations,verbs=get;create;update;delete;list;watch

func (r *QuoteAttestationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	retry := ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}
	if r == nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("nil reconciler")
	}
	l := r.Log.WithValues("reconcile", req.NamespacedName)

	var attestReq v1alpha1.QuoteAttestation

	if err := client.IgnoreNotFound(r.Get(ctx, req.NamespacedName, &attestReq)); err != nil {
		l.V(2).Info("Failed to fetch object", "req", req)
		return retry, err
	}

	if !attestReq.ObjectMeta.DeletionTimestamp.IsZero() {
		// object being deleted, just ignore
		return ctrl.Result{}, nil
	}
	// Do not handle quote attestation request, that supposed to be
	// handled by the signer (CSR, CR) controllers.
	if attestReq.Spec.Type == v1alpha1.RequestTypeQuoteAttestation {
		return ctrl.Result{}, nil
	}

	l.Info("Attestation", "status", attestReq.Status)

	ready := attestReq.Status.GetCondition(v1alpha1.ConditionReady)
	if ready == nil || ready.Status == v1.ConditionUnknown {
		l.V(3).Info("Still waiting for results")
		return retry, nil
	}

	signerName := attestReq.Spec.SignerName
	if ready.Status == v1.ConditionFalse {
		// Secret preperation failure at attestation-controller side
		l.Info("CA secret failure", "reason", ready.Reason, "message", ready.Message)
		if s, _ := r.KeyProvider.GetSignerForName(signerName); s != nil {
			s.SetError(fmt.Errorf("%s:%s", ready.Status, ready.Message))
		}
		return ctrl.Result{}, nil
	}

	// attestation passed. Quote get verified
	l.Info("Using provisioned secrets")
	if provisionError := r.loadSecret(ctx, signerName, attestReq.Spec.SecretName, req.Namespace); provisionError != nil {
		l.Info("CA provisioning", "error", provisionError)
		if s, _ := r.KeyProvider.GetSignerForName(signerName); s != nil {
			s.SetError(provisionError)
		}
		return retry, nil
	}

	l.V(1).Info("Attestation passed. Private key(s) saved to enclave")
	func() {
		k8sutil.QuoteAttestationDelete(context.Background(), r.Client, attestReq.Name, attestReq.Namespace)
	}()

	return ctrl.Result{}, nil
}

func (r *QuoteAttestationReconciler) getEventFilter() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(ce event.CreateEvent) bool {
			qa, ok := ce.Object.(*v1alpha1.QuoteAttestation)
			if !ok {
				r.Log.Info("Not a quote attestation object")
				return false
			}
			// FIXME(avalluri); Initializing status is hack made
			// to work patching status object manually by km-* tools.
			// It should be removed once the attestation-controller used.
			r.Log.Info("QuoteAttestation created, initializing status")
			reqCopy := qa.DeepCopy()
			qa.Status.SetCondition(v1alpha1.ConditionStatusInit, v1.ConditionTrue, v1alpha1.ReasonTCSReconcile, "Object status initialized")
			if err := r.Status().Patch(context.TODO(), qa, client.MergeFrom(reqCopy)); err != nil {
				r.Log.V(3).Error(err, "Failed to update attestation initial status")
			}

			return true
		},
		DeleteFunc: func(de event.DeleteEvent) bool {
			r.Log.V(4).Info("Quote attestation CR got deleted")
			return false
		},
		UpdateFunc: func(ue event.UpdateEvent) bool {
			return false
		},
	}
}

// SetupWatch sets up the controller with the Manager.
func (r *QuoteAttestationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r == nil {
		return fmt.Errorf("nil reconciler")
	}

	return ctrl.NewControllerManagedBy(mgr).For(&v1alpha1.QuoteAttestation{}).
		WithEventFilter(r.getEventFilter()).Complete(r)
}

func (r *QuoteAttestationReconciler) SetupWatch(mgr ctrl.Manager) (controller.Controller, error) {
	if r == nil {
		return nil, fmt.Errorf("nil reconciler")
	}
	c, err := controller.NewUnmanaged("quote-attestion", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return nil, err
	}

	return c, c.Watch(
		&source.Kind{Type: &v1alpha1.QuoteAttestation{}},
		&handler.EnqueueRequestForObject{},
		r.getEventFilter(),
	)
}
