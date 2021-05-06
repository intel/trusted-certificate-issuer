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

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConditionType is the type of a QuoteAttestationCondition
type ConditionType string

// ConditionReason is the shaort machine readable reason for
// the occurred condition.
type ConditionReason string

// Well-known condition types for certificate requests.
const (

	// ConditionStatusInit indicates the condition for object status
	// has just initiated. This is just to allow manual status patching
	// using kubctl, where no attestation-controller is running.
	// NOTE: This mist be removed in near feature.
	ConditionStatusInit ConditionType = "Init"

	// ConditionQuoteVerified indicates the condition for quote verification
	// Must be set by the attestation-controller to update the quote verification
	// state.
	ConditionQuoteVerified ConditionType = "QuoteVerified"
	// ConditionCASecretReady indicates the condition for requested secret(s) are
	// ready. This must be set by the attestation-controller when it fetches
	// the CA encrypted key and certificate and prepared teh secret.
	ConditionCASecretReady ConditionType = "CASecretReady"
	// ConditionReady indicates the condition for the requested signer/CA(s)
	// provision in to HSM token. This must be set by the attestation requester.
	ConditionReady ConditionType = "Ready"

	ReasonTCSReconcile        ConditionReason = "TCSReconcile"
	ReasonControllerReconcile ConditionReason = "AttestationControllerReconcile"

	// ECDSAQuoteVersion3 indicates the SGX ECDSA quote version 3. This is the only
	// supported version by the QVE.
	ECDSAQuoteVersion3 = "ECDSA Quote 3"
)

// QuoteAttestationSpec defines the desired state of QuoteAttestation
type QuoteAttestationSpec struct {
	// Quote to be verified, base64-encoded.
	// +kubebuilder:listType=atomic
	Quote []byte `json:"quote"`

	// QuoteVersion used to for generated quote, default is ECDSA quote "3"
	// +kubebuilder:optional
	QuoteVersion string `json:"quoteVersion,omitempty"`

	//// ServiceID holds the unique identifier(name?) that represents service
	// which is requesting for the secret.
	// To be decided wether this should be SPIFFE trust domain!
	ServiceID string `json:"serviceId"`

	// PublicKey for encrypting the secret, hash is part of the quote data,
	// base-64 encoded.
	// +kubebuilder:listType=atomic
	PublicKey []byte `json:"publicKey"`

	// SignerNames refers to the list of Kubernetes CSR signer names used by
	// this request.
	SignerNames []string `json:"signerNames"`
}

// QuoteAttestationCondition describes a condition of a QuoteAttestation object
type QuoteAttestationCondition struct {
	// type of the condition. One of QuoteVerified, CASecretReady adn Ready
	Type ConditionType `json:"type,omitempty"`
	// Status indicates the status of a condition (true, false, or unknown).
	Status v1.ConditionStatus `json:"status,omitempty"`
	// Reason indicates current request state
	// +optional
	Reason ConditionReason `json:"reason,omitempty"`
	// message contains a human readable message with details about the request state
	// +optional
	Message string `json:"message,omitempty"`
	// lastUpdateTime is the time of the last update to this condition
	// +optional
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`
}

// QuoteAttestationSecret defines the secret get from the Key Management Service
type QuoteAttestationSecret struct {
	// SecretName represents name of the Secret object (in the same namespace)
	// which is opeque type. The secret data must contain two map elements `tls.key`
	// and `tls.cert` and the values are the base64 encoded encrypted CA key and
	// base64 encoded x509(PEM encoded) certificate. This must bed added only after a successful
	// quote validation and before updating the status condition.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// SecretType defines the internal structure of secret fetched from the
	// Key Management Service, as there might be different formats accordingly.
	// +optional
	SecretType string `json:"secretType,omitempty"`
}

// QuoteAttestationStatus defines the observed state of QuoteAttestation
type QuoteAttestationStatus struct {
	// conditions applied to the request. Known conditions are "QuoteVerified",
	// "CASecretsReady" and "Ready".
	// +optional
	Conditions []QuoteAttestationCondition `json:"conditions,omitempty"`

	// Secrets fetched after the request has been processed successfully
	// The map keys are the signer names(Spec.SignerNames) passed by the
	// request.
	// +optional
	Secrets map[string]QuoteAttestationSecret `json:"secrets,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// QuoteAttestation is the Schema for the quoteattestations API
type QuoteAttestation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   QuoteAttestationSpec   `json:"spec,omitempty"`
	Status QuoteAttestationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// QuoteAttestationList contains a list of QuoteAttestation
type QuoteAttestationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []QuoteAttestation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&QuoteAttestation{}, &QuoteAttestationList{})
}

func (qas *QuoteAttestationStatus) SetCondition(t ConditionType, status v1.ConditionStatus, reason ConditionReason, message string) {
	cond := QuoteAttestationCondition{
		Type:           t,
		Status:         status,
		Reason:         reason,
		Message:        message,
		LastUpdateTime: metav1.Now(),
	}
	for i, c := range qas.Conditions {
		if c.Type == t {
			qas.Conditions[i] = cond
			return
		}
	}
	qas.Conditions = append(qas.Conditions, cond)
}

func (qas *QuoteAttestationStatus) GetCondition(t ConditionType) *QuoteAttestationCondition {
	for _, c := range qas.Conditions {
		if c.Type == t {
			return &c
		}
	}
	return nil
}
