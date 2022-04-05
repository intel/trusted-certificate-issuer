/*
Copyright 2021 Intel(R) Corporation.

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
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/internal/k8sutil"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Log                      logr.Logger
	Scheme                   *runtime.Scheme
	ClusterResourceNamespace string
	Kind                     string
	KeyProvider              keyprovider.KeyProvider
}

func (r *IssuerReconciler) newIssuer() (client.Object, error) {
	issuerGVK := tcsapi.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

//+kubebuilder:rbac:groups=tcs.intel.com,resources=tcsissuers;tcsclusterissuers,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=tcs.intel.com,resources=tcsissuers/status;tcsclusterissuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update;delete;patch;list;watch
//+kubebuilder:rbac:groups="",resources=secrets/finalizers,verbs=get;update;patch

func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognized issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := IssuerSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	// Always attempt to update the Ready condition
	defer func() {
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := issuerStatus.GetCondition(tcsapi.IssuerConditionReady); ready == nil {
		issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionUnknown, "Reconcile", "First seen")
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	}

	signerName := r.signerNameForIssuer(issuer)
	s, err := r.KeyProvider.GetSignerForName(signerName)
	if errors.Is(err, keyprovider.ErrNotFound) {
		log.Info("Adding new signer for", "issuer", req.Name)
		if s, err = r.KeyProvider.AddSigner(signerName, issuerSpec.SelfSignCertificate); err != nil {
			log.Info("Initializing the Issuer signer failed", "issuer", req.Name, "error", err)
			issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", err.Error())
			return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
		}
	}
	if err != nil {
		log.Info("Initializing the Issuer signer failed", "error", err)
		issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", err.Error())
		return ctrl.Result{}, err
	}

	if !s.Ready() {
		log.Info("Still waiting for signer to be initialized", "issuer", req.Name)
		issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", "Signer is not ready")
		return ctrl.Result{Requeue: true, RequeueAfter: 10 * time.Second}, nil
	}

	log.Info("Signer is ready for", "issuer", req.Name)

	if issuerSpec.SecretName != "" {
		ns := req.Namespace
		if ns == "" {
			ns = k8sutil.GetNamespace()
		}
		ownerRef := metav1.OwnerReference{
			APIVersion: tcsapi.GroupVersion.String(),
			Kind:       issuer.GetObjectKind().GroupVersionKind().Kind,
			Name:       issuer.GetName(),
			UID:        issuer.GetUID(),
		}
		if err := k8sutil.CreateCASecret(context.TODO(), r.Client, s.Certificate(), issuerSpec.SecretName, ns, ownerRef); err != nil {
			log.Info("failed to create issuer secret", "error", err)
			issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", err.Error())
			return ctrl.Result{RequeueAfter: time.Minute}, err
		}
	}
	issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionTrue, "Reconcile", "Success")
	log.Info("Issuer Status Condition(s)", "conditions", issuerStatus.Conditions)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return nil
	}
	return ctrl.NewControllerManagedBy(mgr).For(issuerType).WithEventFilter(predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			signerName := r.signerNameForIssuer(e.Object)
			r.Log.Info("Removing CA stored token for deleted issuer", "issuer", signerName)
			r.KeyProvider.RemoveSigner(signerName)
			r.Log.Info("Removing CA secrets for deleted issuer", "issuer", signerName)
			issuerSpec, _, err := IssuerSpecAndStatus(e.Object)
			if err != nil {
				r.Log.Error(err, "Unexpected error while getting issuer spec and status.")
				return false
			}

			ns := e.Object.GetNamespace()
			if r.Kind == "TCSClusterIssuer" {
				ns = k8sutil.GetNamespace()
			}
			secret := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuerSpec.SecretName,
					Namespace: ns,
				},
			}
			ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(time.Minute))
			defer cancel()
			if err := k8sutil.UnsetFinalizer(ctx, r.Client, secret, func() client.Object {
				return secret.DeepCopy()
			}); err != nil {
				r.Log.Info("Failed to update finalizer", "issuer", signerName, "error", err)
			}
			return false
		},
		UpdateFunc: func(ue event.UpdateEvent) bool { return false },
	}).Complete(r)
}

func (r *IssuerReconciler) signerNameForIssuer(issuer client.Object) string {
	return SignerNameForIssuer(tcsapi.GroupVersion.WithKind(r.Kind), issuer.GetName(), issuer.GetNamespace())
}
