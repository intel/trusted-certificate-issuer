package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	"github.com/intel/trusted-certificate-issuer/internal/signer"
	"github.com/intel/trusted-certificate-issuer/internal/tlsutil"
)

const certificateDuration = time.Hour * 24

type SignerError struct {
	Name       string
	ErrMessage string
}
type Config struct {
	KnownSigners         []string
	AddSignerError       SignerError
	ProvisionSignerError SignerError
}

type fakeKeyProvider struct {
	signers map[string]*signer.Signer
	cfg     Config
}

var _ keyprovider.KeyProvider = &fakeKeyProvider{}

func NewKeyProvider(cfg Config) keyprovider.KeyProvider {
	signers := map[string]*signer.Signer{}
	for _, name := range cfg.KnownSigners {
		signers[name] = signer.NewSigner(name)
	}
	return &fakeKeyProvider{
		signers: signers,
		cfg:     cfg,
	}
}

func (kp *fakeKeyProvider) SignerNames() []string {
	names := []string{}
	for s := range kp.signers {
		names = append(names, s)
	}

	return names
}

func (kp *fakeKeyProvider) AddSigner(name string, selfSign bool) (*signer.Signer, error) {
	if kp.cfg.AddSignerError.Name != "" && strings.HasSuffix(name, kp.cfg.AddSignerError.Name) {
		return nil, errors.New(kp.cfg.AddSignerError.ErrMessage)
	}
	if s, ok := kp.signers[name]; ok {
		return s, nil
	}

	s := signer.NewSigner(name)
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	cert, err := NewCACertificate(key, time.Now(), certificateDuration, true)
	if err != nil {
		return nil, err
	}
	s.SetReady(key, cert)
	kp.signers[name] = s
	return s, nil
}

func (kp *fakeKeyProvider) RemoveSigner(name string) error {
	if _, ok := kp.signers[name]; ok {
		kp.signers[name] = nil
		delete(kp.signers, name)
	}
	return nil
}

func (kp *fakeKeyProvider) GetSignerForName(signerName string) (*signer.Signer, error) {
	s, ok := kp.signers[signerName]
	if !ok {
		return nil, keyprovider.ErrNotFound
	}

	return s, nil
}

func (kp *fakeKeyProvider) ProvisionSigner(signerName string, base64Key []byte, cert *x509.Certificate) (*signer.Signer, error) {
	if kp.cfg.ProvisionSignerError.Name != "" && strings.HasSuffix(signerName, kp.cfg.ProvisionSignerError.Name) {
		return nil, errors.New(kp.cfg.ProvisionSignerError.ErrMessage)
	}
	s := signer.NewSigner(signerName)
	key, err := tlsutil.DecodeKey(base64Key)
	if err != nil {
		return nil, fmt.Errorf("corrupted key data: %v", err)
	}

	s.SetReady(key, cert)
	kp.signers[signerName] = s
	return s, nil
}

func (kp *fakeKeyProvider) GetQuote(string) (*keyprovider.QuoteInfo, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &keyprovider.QuoteInfo{
		Quote:     []byte("DummyQuote"),
		PublicKey: &key.PublicKey,
		Nonce:     []byte{},
	}, nil
}
