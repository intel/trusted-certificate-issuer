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
	// using kubectl, where no attestation-controller is running.
	// NOTE: This must be removed in near feature.
	ConditionStatusInit ConditionType = "Init"

	// ConditionReady indicates the condition for the request is ready
	// This should be set by the attestation-controller upon request has
	// been resolved, i.e. either success or failure.
	ConditionReady ConditionType = "Ready"

	ReasonTCSReconcile        ConditionReason = "TCSReconcile"
	ReasonControllerReconcile ConditionReason = "AttestationControllerReconcile"

	// ECDSAQuoteVersion3 indicates the SGX ECDSA quote version 3. This is the only
	// supported version by the QVE.
	ECDSAQuoteVersion3 = "ECDSA Quote 3"
)

// QuoteAttestationRequestType type definition for representing
// the type of attestation request
type QuoteAttestationRequestType string

const (
	// RequestTypeQuoteAttestation represents the type of request
	// is for only quote verification
	RequestTypeQuoteAttestation = "QuoteAttestation"
	// RequestTypeKeyProvisioning represents the type of request
	// is for CA key provisioning where quote verification is a
	// pre-requisite
	RequestTypeKeyProvisioning = "KeyProvisioning"
)

// QuoteAttestationSpec defines the desired state of QuoteAttestation
type QuoteAttestationSpec struct {
	// Type represents the type of the request, one of "QuoteAttestation", "KeyProvisioning".
	// +kubebuilder:validation:Enum=QuoteAttestation;KeyProvisioning
	// +kubebuilder:validation:default=KeyProvisioning
	Type QuoteAttestationRequestType `json:"type"`
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

	// SignerName refers to the Kubernetes CSR signer name used by
	// this request.
	SignerName string `json:"signerName"`

	// SecretName is name of the Secret object (in the same namespace)
	// to keep the wrapped on secrets (only needed for KeyProvisioning request type)
	// which is an opeque type. The secret data must contain two map elements `tls.key`
	// and `tls.cert` and the values are the base64 encoded encrypted CA key and
	// base64 encoded x509(PEM encoded) certificate. This must be added only after
	// a successful quote validation and before updating the status condition.
	// +optional
	SecretName string `json:"secretName,omitempty"`
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

// QuoteAttestationStatus defines the observed state of QuoteAttestation
type QuoteAttestationStatus struct {
	// conditions applied to the request. Known conditions are "QuoteVerified",
	// "CASecretsReady" and "Ready".
	// +optional
	Conditions []QuoteAttestationCondition `json:"conditions,omitempty"`
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
