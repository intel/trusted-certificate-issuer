/*
Copyright 2023 Intel(R)
SPDX-License-Identifier: Apache-2.0
*/

package sgxutils

/*
typedef unsigned long int CK_ULONG;
typedef void * CK_BYTE_PTR;
typedef struct CK_RSA_PUBLIC_KEY_PARAMS {
	CK_ULONG ulExponentLen;
	CK_ULONG ulModulusLen;
} CK_RSA_PUBLIC_KEY_PARAMS;

CK_ULONG quote_offset(CK_BYTE_PTR bytes) {
	CK_RSA_PUBLIC_KEY_PARAMS* params = (CK_RSA_PUBLIC_KEY_PARAMS*)bytes;
	if (params == NULL) {
		return 0;
	}
	CK_ULONG pubKeySize = params->ulModulusLen + params->ulExponentLen;
	// check for overflow
	if (pubKeySize < params->ulModulusLen || pubKeySize < params->ulExponentLen) {
		return 0;
	}
    CK_ULONG offset = sizeof(CK_RSA_PUBLIC_KEY_PARAMS) + pubKeySize;

	return offset;
}

CK_ULONG rsa_key_params_size() {
    return (CK_ULONG)sizeof(CK_RSA_PUBLIC_KEY_PARAMS);
}

CK_ULONG ulExponentLen_offset(CK_BYTE_PTR bytes) {
	CK_RSA_PUBLIC_KEY_PARAMS* params = (CK_RSA_PUBLIC_KEY_PARAMS*)bytes;
	if (params == NULL) {
		return 0;
	}
	return params->ulExponentLen;
}
*/
import "C"
import (
	"crypto/rsa"
	"fmt"
	"math"
	"math/big"
	"unsafe"
)

// ParseQuotePublickey reconstruct the rsa public key
// from received bytes, received bytes structure like this:
// pubkey_params   |    ulExponentLen   |    ulModulusLen
// need to slice ulExponentLen and ulModulusLen to
// reconstruct pubkey according to the size of each item
func ParseQuotePublickey(pubkey []byte) (*rsa.PublicKey, error) {
	paramsSize := uint64(C.rsa_key_params_size())
	exponentLen := uint64(C.ulExponentLen_offset(*(*C.CK_BYTE_PTR)(unsafe.Pointer(&pubkey))))
	modulusOffset := paramsSize + exponentLen
	if modulusOffset >= uint64(len(pubkey)) {
		return nil, fmt.Errorf("malformed quote public key: out of bounds")
	}

	var bigExponent = new(big.Int)
	bigExponent.SetBytes(pubkey[paramsSize:modulusOffset])
	if bigExponent.BitLen() > 32 || bigExponent.Sign() < 1 {
		return nil, fmt.Errorf("malformed quote public key")
	}
	if bigExponent.Uint64() > uint64(math.MaxInt) {
		return nil, fmt.Errorf("malformed quote public key: possible data loss in exponent value")
	}
	exponent := int(bigExponent.Uint64())
	var modulus = new(big.Int)
	modulus.SetBytes(pubkey[modulusOffset:])
	return &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}, nil
}

// QuoteOffset returns the offset of SGX quote in the
// given quotePublicKey bytes returns by the CTK while
// generating the quote.
func QuoteOffset(quotePublicKey []byte) uint64 {
	return uint64(C.quote_offset(*(*C.CK_BYTE_PTR)(unsafe.Pointer(&quotePublicKey))))
}
