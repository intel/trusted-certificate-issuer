/*
Copyright 2022.

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
	"context"
)

type Plugin interface {
	// Name returns the name of the key server
	Name() string

	// Endpoint returns the plugin's socket path
	Endpoint() string

	// IsReady return if the connection the key server is ready
	IsReady() bool

	// GetCASecret retrieves the stored CA key and certificate at the key-manager
	// for given signer signerName. Both quote and publicKey are base64 encoded.
	// First the given SGX quote is validated is valid by using quote validation library.
	// The publickey hash part of the quote must match with the given publicKey.
	//
	// On success, returns the key and certificate. The CA private key(PWK) is wrapped
	// with a symmetric key(SWK) that was wrapped with the given publicKey. Both the
	// SWK and PWK are concatenated and returned as single base64 encoded block. Certificate
	// is base64 encoded.
	// Otherwise, appropriate error gets returned.
	GetCASecret(ctx context.Context, signerName string, quote []byte, publicKey []byte) ([]byte, []byte, error)
}
