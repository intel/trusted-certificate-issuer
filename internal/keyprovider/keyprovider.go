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
package keyprovider

import (
	"crypto/x509"
	"errors"

	"github.com/intel/trusted-certificate-issuer/internal/signer"
)

var ErrNotFound = errors.New("NotFound")

type KeyProvider interface {
	// SignerNames lists all the valid signer names, the list
	// might also contains the pending signers.
	SignerNames() []string

	// AddSigner starts process of initiating a new signer withe given name.
	// Returns error if it fails do so. Adding signer is an asynchronous process.
	// Use GetSignerForName() to retrieve the initialized signer.
	AddSigner(signerName string, selfSign bool) (*signer.Signer, error)

	// RemoveSigner removes the secrets stored for the given signerName.
	RemoveSigner(signerName string) error

	// GetSignerForName returns the available signer for give signerName.
	// Returns "not found" error if the given signerName is not found in the list.
	// Returns any other error occurred while provisioning the CA.
	GetSignerForName(signerName string) (*signer.Signer, error)

	// ProvisionSigner stores the given CA key and certificate for the signerName.
	// The key must be encrypted with the given publick-key used while quote-generation.
	ProvisionSigner(signerName string, encryptedKey []byte, cert *x509.Certificate) (*signer.Signer, error)

	// GetQuoteAndPublicKey returns SGX quote and the publickey used for generating the quote
	GetQuoteAndPublicKey() ([]byte, interface{}, error)
}
