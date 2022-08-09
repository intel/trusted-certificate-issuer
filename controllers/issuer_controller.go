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
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/intel/trusted-certificate-issuer/internal/signer"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
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
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations,verbs=get;list;watch;create;delete;patch
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=tcs.intel.com,resources=quoteattestations/finalizers,verbs=update
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

	ready := issuerStatus.GetCondition(tcsapi.IssuerConditionReady)
	if ready == nil {
		issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionUnknown, "Reconcile", "First seen")
		return ctrl.Result{Requeue: true}, nil
	}
	if ready.Status == v1.ConditionTrue {
		log.Info("Ignoring as the issuer is ready")
		return ctrl.Result{}, nil
	}

	signerName := r.signerNameForIssuer(issuer)
	s, err := r.KeyProvider.GetSignerForName(signerName)
	if errors.Is(err, keyprovider.ErrNotFound) {
		if issuerSpec.SelfSignCertificate != nil && *issuerSpec.SelfSignCertificate {
			log.Info("Adding new signer for", "issuer", req.Name)
			if s, err = r.KeyProvider.AddSigner(signerName, true); err != nil {
				log.Info("Initializing the Issuer signer failed", "issuer", req.Name, "error", err)
				issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", err.Error())
				return ctrl.Result{Requeue: false}, nil
			}
		} else {
			qa := &tcsapi.QuoteAttestation{}
			qaReq := req.NamespacedName
			if qaReq.Namespace == "" {
				qaReq.Namespace = k8sutil.GetNamespace()
			}
			if err := r.Get(ctx, qaReq, qa); err != nil {
				if apierrors.IsNotFound(err) {
					// means no quoteattestation object, create new one
					quote, publickey, err := r.KeyProvider.GetQuoteAndPublicKey(signerName)
					if err != nil {
						log.Info("Error preparing SGX quote", "error", err)
						issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", fmt.Sprintf("failed to get sgx quote: %v", err.Error()))
						return ctrl.Result{Requeue: true}, nil
					}
					ownerRef := &metav1.OwnerReference{
						APIVersion: tcsapi.GroupVersion.String(),
						Kind:       r.Kind,
						Name:       issuer.GetName(),
						UID:        issuer.GetUID(),
					}
					log.Info("Initiating quote attestation", "signer", signerName)
					if err := k8sutil.QuoteAttestationDeliver(ctx, r.Client, qaReq, tcsapi.RequestTypeKeyProvisioning, signerName, quote, publickey, "", ownerRef); err != nil {
						log.Error(err, "Error while creating quote attestation")
						issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", fmt.Sprintf("failed to initiate quote attestation: %v", err.Error()))
						return ctrl.Result{Requeue: true}, nil
					}

					issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", "Initiated key provisioning using QuoteAttestation")
					return ctrl.Result{Requeue: true}, nil
				}
				log.Error(err, "Error while checking if quote attestation exists")
				issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", fmt.Sprintf("failed to get quote attestation status: %v", err.Error()))
				return ctrl.Result{Requeue: true}, nil
			}
			status := qa.Status.GetCondition(tcsapi.ConditionReady)
			if status == nil || status.Status == v1.ConditionUnknown {
				// Still not ready, retry later
				issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", "Waiting for key provisioning")
				return ctrl.Result{Requeue: true}, nil
			}

			// Remove attestation object as we got the results
			defer k8sutil.QuoteAttestationDelete(context.Background(), r.Client, qaReq)

			if status.Status == v1.ConditionFalse {
				// Secret delivery failure
				issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", fmt.Sprintf("%s: %s", status.Status, status.Message))
				return ctrl.Result{}, nil
			}

			s, err = r.provisionSigner(ctx, signerName, qa.Spec.SecretName, qa.Namespace)
		}
	}

	if err != nil {
		log.Info("Failed initializing the Issuer", "error", err)
		issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", err.Error())
		return ctrl.Result{}, nil
	}

	if !s.Ready() {
		log.Info("Still waiting for signer to be initialized", "issuer", req.Name)
		issuerStatus.SetCondition(tcsapi.IssuerConditionReady, v1.ConditionFalse, "Reconcile", "Signer is not ready")
		return ctrl.Result{Requeue: true}, nil
	}

	log.Info("Signer is ready for", "issuer", req.Name)

	if issuerSpec.SecretName != "" {
		ns := req.Namespace
		if ns == "" {
			ns = k8sutil.GetNamespace()
		}
		ownerRef := metav1.OwnerReference{
			APIVersion: tcsapi.GroupVersion.String(),
			Kind:       r.Kind,
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
				r.Log.Info("Failed to update finalizer on Secret", "issuer", signerName, "error", err)
			}

			qa := &tcsapi.QuoteAttestation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      e.Object.GetName(),
					Namespace: ns,
				},
			}
			if err := k8sutil.UnsetFinalizer(ctx, r.Client, qa, func() client.Object {
				return qa.DeepCopy()
			}); err != nil {
				r.Log.Info("Failed to update finalizer on QuoteAttestation", "issuer", signerName, "error", err)
			}

			return false
		},
		UpdateFunc: func(ue event.UpdateEvent) bool { return false },
	}).Complete(r)
}

func (r *IssuerReconciler) signerNameForIssuer(issuer client.Object) string {
	return SignerNameForIssuer(tcsapi.GroupVersion.WithKind(r.Kind), issuer.GetName(), issuer.GetNamespace())
}

func (r *IssuerReconciler) provisionSigner(ctx context.Context, signerName, secretName, namespace string) (*signer.Signer, error) {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Name: secretName, Namespace: namespace}

	if err := r.Get(ctx, key, secret); err != nil {
		r.Log.Error(err, "Failed to get secret", "secret", secret, "signer", signerName)
		return nil, err
	}

	wrappedKey, ok := secret.Data[v1.TLSPrivateKeyKey]
	if !ok || len(wrappedKey) == 0 {
		return nil, fmt.Errorf("invalid secret: missing CA private key")
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(string(wrappedKey))
	if err != nil {
		return nil, fmt.Errorf("corrupted key data: %v", err)
	}

	encCert, ok := secret.Data[v1.TLSCertKey]
	if !ok || len(encCert) == 0 {
		return nil, fmt.Errorf("invalid secret: missing CA certificate")
	}

	pemCert, err := base64.StdEncoding.DecodeString(string(encCert))
	if err != nil {
		return nil, fmt.Errorf("corrupted certificate: %v", err)
	}

	cert, err := tlsutil.DecodeCert(pemCert)
	if err != nil {
		return nil, fmt.Errorf("corrupted certificate: %v", err)
	}

	return r.KeyProvider.ProvisionSigner(signerName, encryptedKey, cert)
}
