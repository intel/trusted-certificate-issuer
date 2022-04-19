package testutils

import (
	"crypto/x509"
	"fmt"

	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/signer"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
)

type fakeKeyProvider struct {
	signers map[string]*signer.Signer
}

var _ keyprovider.KeyProvider = &fakeKeyProvider{}

func NewKeyProvider(signers map[string]*signer.Signer) keyprovider.KeyProvider {
	return &fakeKeyProvider{
		signers: signers,
	}
}

func (kp *fakeKeyProvider) SignerNames() []string {
	names := []string{}
	for s := range kp.signers {
		names = append(names, s)
	}

	return names
}

func (kå *fakeKeyProvider) AddSigner(name string, selfSign bool) (*signer.Signer, error) {
	return nil, fmt.Errorf("not implemented")
}

func (kå *fakeKeyProvider) RemoveSigner(name string) error {
	return fmt.Errorf("not implemented")
}

func (kp *fakeKeyProvider) GetSignerForName(signerName string) (*signer.Signer, error) {
	s, ok := kp.signers[signerName]
	if !ok {
		return nil, fmt.Errorf("unknown signer")
	}
	/*s := signer.NewSigner(signerName)
	if ca != nil {
		s.SetReady(ca.PrivateKey(), ca.Certificate())
	}*/

	return s, nil
}

func (kp *fakeKeyProvider) ProvisionSigner(signerName string, base64Key []byte, cert *x509.Certificate) ([]byte, error) {
	s, ok := kp.signers[signerName]
	if !ok || s == nil {
		return nil, fmt.Errorf("unknown signer '%s'", signerName)
	}
	key, err := tlsutil.DecodeKey(base64Key)
	if err != nil {
		return nil, fmt.Errorf("corrupted key data: %v", err)
	}

	s.SetReady(key, cert)
	return nil, nil
}

func (kp *fakeKeyProvider) GetQuoteAndPublicKey() ([]byte, interface{}, error) {
	return nil, nil, fmt.Errorf("not implemented")
}
