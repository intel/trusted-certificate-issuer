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

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TCSIssuerSpec defines the desired state of Issuer
type TCSIssuerSpec struct {
	// SecretName is the name of the secret object to be
	// created by issuer controller to hold ca certificate
	SecretName string `json:"secretName,omitempty"`
	// SelfSignCertificate defines weather to generate a self-signed certificate
	// for this CA issuer. When it set false, the CA is expected to get provisioned
	// by an external key server using QuoteAttestaion CRD.
	// Default to True.
	// +kubebuilder:default=true
	SelfSignCertificate bool `json:"selfSign,omitempty"`
}

// TCSIssuerStatus defines the observed state of Issuer
type TCSIssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	// +optional
	Conditions []TCSIssuerCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
//+kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type=='Ready')].status`
//+kubebuilder:printcolumn:name="Reason",type="string",JSONPath=`.status.conditions[?(@.type=='Ready')].reason`
//+kubebuilder:printcolumn:name="Message",type="string",JSONPath=`.status.conditions[?(@.type=='Ready')].message`
// TCSIssuer is the Schema for the issuers API
type TCSIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TCSIssuerSpec   `json:"spec,omitempty"`
	Status TCSIssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
// TCSIssuerList contains a list of TCSIssuer
type TCSIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TCSIssuer `json:"items"`
}

// IssuerCondition contains condition information for an Issuer.
type TCSIssuerCondition struct {
	// Type of the condition, known values are ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status v1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	IssuerConditionReady IssuerConditionType = "Ready"
)

func init() {
	SchemeBuilder.Register(&TCSIssuer{}, &TCSIssuerList{})
}

func (status *TCSIssuerStatus) GetCondition(ct IssuerConditionType) *TCSIssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == ct {
			return &c
		}
	}
	return nil
}

func (status *TCSIssuerStatus) SetCondition(ct IssuerConditionType, condStatus v1.ConditionStatus, reason, message string) {
	cond := status.GetCondition(ct)
	if cond == nil {
		cond = &TCSIssuerCondition{
			Type:   ct,
			Status: condStatus,
		}
		status.Conditions = append(status.Conditions, *cond)
	}
	cond.Status = condStatus
	cond.Message = message
	cond.Reason = reason
	if cond.Status == condStatus {
		cond.Status = condStatus
		now := metav1.Now()
		cond.LastTransitionTime = &now
	}
	for i, c := range status.Conditions {
		if c.Type == ct {
			status.Conditions[i] = *cond
			return
		}
	}
}
