/*
Copyright 2021 Intel(R)
SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"crypto/x509"
	"sync"
)

type SignerState string

const (
	// New signer whose secrets are not available
	// with the operator.
	new SignerState = "New"
	// Pending represents a pending attestation request for the signer.
	pending SignerState = "Pending"
	// Ready represents the signer secrets are available and
	// is ready serving.
	ready SignerState = "Ready"
	// Failed represents some error has occurred while initializing
	// the signer.
	failed SignerState = "Failed"
)

type attestationRequest struct {
	name, namespace string
}

type Signer struct {
	crypto.Signer
	cert  *x509.Certificate
	name  string
	state SignerState
	err   error
	req   attestationRequest
}

func NewSigner(name string) *Signer {
	return &Signer{name: name, state: new}
}

func (s Signer) Name() string {
	return s.name
}

func (s Signer) NotInitialized() bool {
	return s.state == new
}

func (s Signer) Ready() bool {
	return s.state == ready
}

// Pending returns if the signer is in pending state
func (s Signer) Pending() bool {
	return s.state == pending
}

// AttestationCRName returns the name of the attestation request
// name in case of a pending signer.
func (s Signer) AttestationCRNameAndNamespace() (string, string) {
	return s.req.name, s.req.namespace
}

func (s Signer) Failed() (bool, error) {
	if s.state == failed {
		return true, s.err
	}
	return false, nil
}

func (s Signer) Error() error {
	return s.err
}

func (s Signer) Certificate() *x509.Certificate {
	if s.state == ready {
		return s.cert
	}
	return nil
}

func (s *Signer) SetError(err error) {
	if s.state != failed {
		s.state = failed
		s.err = err
	}
}

func (s *Signer) SetPending(requestName, namespace string) {
	if s.state != pending {
		s.state = pending
		s.req = attestationRequest{
			name:      requestName,
			namespace: namespace,
		}
	}
}

func (s *Signer) SetReady(cs crypto.Signer, cert *x509.Certificate) {
	s.state = ready
	s.Signer = cs
	s.cert = cert
	s.err = nil
	s.req = attestationRequest{}
}

type SignerMap struct {
	signers map[string]*Signer
	lock    sync.RWMutex
}

func NewSignerMap() *SignerMap {
	return &SignerMap{
		signers: map[string]*Signer{},
		lock:    sync.RWMutex{},
	}
}

func (sm *SignerMap) Names() []string {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	names := []string{}
	for name, _ := range sm.signers {
		names = append(names, name)
	}
	return names
}

func (sm *SignerMap) Get(name string) *Signer {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	return sm.signers[name]
}

func (sm *SignerMap) PendingSigners() []*Signer {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	pending := []*Signer{}
	for _, s := range sm.signers {
		if ok := s.Pending(); ok {
			pending = append(pending, s)
		}
	}
	return pending
}

func (sm *SignerMap) UnInitializedSigners() []*Signer {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	uninitialized := []*Signer{}
	for _, s := range sm.signers {
		if s.NotInitialized() {
			uninitialized = append(uninitialized, s)
		}
	}
	return uninitialized
}

func (sm *SignerMap) Add(s *Signer) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if _, ok := sm.signers[s.name]; !ok {
		sm.signers[s.name] = s
	}
}

func (sm *SignerMap) Delete(s *Signer) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	delete(sm.signers, s.name)
}
