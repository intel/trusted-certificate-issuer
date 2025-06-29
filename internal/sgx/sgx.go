/*
Copyright 2021 Intel(R)
SPDX-License-Identifier: Apache-2.0
*/

package sgx

/*
#cgo CFLAGS: -g -Wall -I /usr/local/include
#cgo LDFLAGS: -lp11sgx -L /usr/local/lib

#include <cryptoki.h>
#include <QuoteGeneration.h>
*/
import "C"

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os/exec"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ThalesIgnite/crypto11"
	"github.com/go-logr/logr"
	"github.com/intel/trusted-certificate-issuer/internal/config"
	"github.com/intel/trusted-certificate-issuer/internal/keyprovider"
	selfca "github.com/intel/trusted-certificate-issuer/internal/self-ca"
	"github.com/intel/trusted-certificate-issuer/internal/sgxutils"
	"github.com/intel/trusted-certificate-issuer/internal/signer"
	"github.com/miekg/pkcs11"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	SgxLibrary                 = "/usr/local/lib/libp11sgx.so"
	EnclaveQuoteKeyObjectLabel = "Enclave Quote"
	RSAKeySize                 = 3072
)

type quoteInfo struct {
	*keyprovider.QuoteInfo
	// private key used for quote generation
	prvKeyHandle pkcs11.ObjectHandle
	// private key used for quote generation
	pubKeyHandle pkcs11.ObjectHandle
}

type SgxContext struct {
	// pkcs11 is needed for quote generation.
	// There is no way to wrap/unwrap key using crypto11
	p11Ctx *pkcs11.Ctx
	// session opened for quote generation
	p11Session pkcs11.SessionHandle

	quotes    map[string]*quoteInfo
	cryptoCtx *crypto11.Context
	ctxLock   sync.Mutex
	cfg       *config.Config
	k8sClient client.Client
	signers   *signer.SignerMap
	log       logr.Logger
}

var _ keyprovider.KeyProvider = &SgxContext{}

func NewContext(cfg config.Config, client client.Client) (*SgxContext, error) {
	ctx := &SgxContext{
		cfg:       &cfg,
		k8sClient: client,
		log:       ctrl.Log.WithName("SGX"),
		signers:   signer.NewSignerMap(),
		quotes:    map[string]*quoteInfo{},
	}

	if err := ctx.reloadCryptoContext(); err != nil {
		if err.Error() == "could not find PKCS#11 token" /* crypto11.errNotFoundError */ {
			ctx.log.V(3).Info("No existing token found, creating new token...")
			if err := ctx.initializeToken(); err != nil {
				return nil, err
			}
		} else {
			ctx.log.V(2).Info("Failed to configure command")
			return nil, err
		}
	}

	// provision CA key using QuoteAttestation CRD
	ctx.p11Ctx = pkcs11.New(SgxLibrary)

	ctx.log.Info("Initiating p11Session...")
	sh, err := initP11Session(ctx.p11Ctx, cfg.HSMConfig.TokenLabel, cfg.HSMConfig.UserPin, cfg.HSMConfig.SoPin)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	ctx.p11Session = sh

	return ctx, nil
}

func (ctx *SgxContext) Destroy() {
	ctx.destroyP11Context()
	ctx.destroyCryptoContext()
}

func (ctx *SgxContext) TokenLabel() (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("invalid SGX context")
	}
	return ctx.cfg.HSMConfig.TokenLabel, nil
}

func (ctx *SgxContext) GetQuote(signerName string) (*keyprovider.QuoteInfo, error) {
	if ctx == nil {
		return nil, fmt.Errorf("invalid SGX context")
	}

	return ctx.ensureQuote(signerName)
}

func (ctx *SgxContext) SignerNames() []string {
	if ctx == nil {
		return []string{}
	}

	return ctx.signers.Names()
}

func (ctx *SgxContext) addSigner(name string) (*signer.Signer, error) {
	if s := ctx.signers.Get(name); s != nil {
		// It is not an error to call multiple adds on a signer
		ctx.log.Info("Ignore add signer as already exists", "signerName", name)
		return s, nil
	}

	s := signer.NewSigner(name)
	ctx.signers.Add(s)

	key, cert, err := ctx.findSignerInToken(name)
	if err == nil {
		ctx.log.Info("Reusing CA key and certificate from token", "signerName", name)
		s.SetReady(key, cert)
		return s, nil
	}
	return s, err
}

func (ctx *SgxContext) AddSigner(name string, selfSign bool) (*signer.Signer, error) {
	if ctx == nil || ctx.cryptoCtx == nil {
		return nil, fmt.Errorf("sgx context not initialized")
	}

	s, err := ctx.addSigner(name)
	if err != nil && errors.Is(err, keyprovider.ErrNotFound) {
		if selfSign {
			return s, ctx.initializeSigner(s)
		}
	}
	return s, err
}

func (ctx *SgxContext) findSignerInToken(name string) (crypto11.Signer, *x509.Certificate, error) {
	ctx.log.Info("Finding CA key and certificate from token", "for signer", name)

	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()

	cert, errCert := ctx.cryptoCtx.FindCertificate(nil, []byte(name), nil)
	key, errKey := ctx.cryptoCtx.FindKeyPair(nil, []byte(name))
	if cert != nil && key != nil {
		ctx.log.Info("CA details found in token", "for signer", name)
		return key, cert, nil
	}

	if cert != nil {
		if err := ctx.cryptoCtx.DeleteCertificate(nil, []byte(name), nil); err != nil {
			ctx.log.Info("Failed to delete obsolete certificate", "error", err)
		}
	} else if key != nil {
		if err := key.Delete(); err != nil {
			ctx.log.Info("Failed to delete obsolete key", "error", err)
		}
	} else if errKey == nil && errCert == nil {
		ctx.log.Info("No CA details found  in token", "signer", name)
	} else {
		ctx.log.Info("Failed to load CA from token", "certErr", errCert, "keyErr", errKey)
	}
	return nil, nil, keyprovider.ErrNotFound
}

func (ctx *SgxContext) removeSignerInToken(s *signer.Signer) error {
	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()
	if err := s.Signer.(crypto11.Signer).Delete(); err != nil {
		return err
	}
	if err := ctx.cryptoCtx.DeleteCertificate(nil, []byte(s.Name()), nil); err != nil {
		return err
	}
	return nil
}

func (ctx *SgxContext) RemoveSigner(name string) error {
	if ctx == nil || ctx.cryptoCtx == nil {
		return fmt.Errorf("sgx context not initialized")
	}

	s := ctx.signers.Get(name)
	if s == nil {
		if quoteInfo, ok := ctx.quotes[name]; ok {
			ctx.p11Ctx.DestroyObject(ctx.p11Session, quoteInfo.prvKeyHandle) // nolint: errcheck
			ctx.p11Ctx.DestroyObject(ctx.p11Session, quoteInfo.pubKeyHandle) // nolint: errcheck
			delete(ctx.quotes, name)
		}
		return nil
	}
	if s.Ready() {
		if err := ctx.removeSignerInToken(s); err != nil {
			return err
		}
	}

	ctx.signers.Delete(s)

	return nil
}

func (ctx *SgxContext) GetSignerForName(name string) (*signer.Signer, error) {
	if ctx == nil || ctx.cryptoCtx == nil {
		return nil, fmt.Errorf("sgx context not initialized")
	}

	s := ctx.signers.Get(name)
	if s == nil {
		/* If not found in the cache, check in the token */
		key, cert, err := ctx.findSignerInToken(name)
		if err != nil {
			return nil, keyprovider.ErrNotFound
		}
		s := signer.NewSigner(name)
		s.SetReady(key, cert)
		ctx.signers.Add(s)
		return s, nil
	}

	if err := s.Error(); err != nil {
		return nil, err
	}

	return s, nil
}

func (ctx *SgxContext) ProvisionSigner(signerName string, encryptedKey []byte, cert *x509.Certificate) (*signer.Signer, error) {
	if ctx == nil {
		return nil, fmt.Errorf("invalid SGX context")
	}

	s := ctx.signers.Get(signerName)
	if s == nil {
		s = signer.NewSigner(signerName)
	}

	keySizeBytes := RSAKeySize / 8

	if len(encryptedKey) <= keySizeBytes {
		return nil, fmt.Errorf("invalid wrapped key length")
	}

	if err := ctx.provisionCertificate(signerName, cert); err != nil {
		return nil, fmt.Errorf("failed to provision certificate for signer '%s': %v", signerName, err)
	}

	// Wrapped SWK - AES256 (with input public key) + Wrapped input private key (with SWK),
	// bytes concatenated and then encoded with base64 - After decoding with base64,
	// the first 384 bytes (3072 bits - it depends on the length of the input public key)
	// is SWK key (AES), the rest is a wrapped private key in PKCS#8 format
	wrappedSwk := encryptedKey[:keySizeBytes]
	wrappedPrKey := encryptedKey[keySizeBytes:]

	_, err := ctx.provisionKey(signerName, wrappedSwk, wrappedPrKey)
	if err != nil {
		if err := ctx.cryptoCtx.DeleteCertificate(nil, []byte(signerName), nil); err != nil {
			ctx.log.Info("Failed remove certificate for incomplete provision", "error", err)
		}
		return nil, fmt.Errorf("failed to provision key for signer '%s': %v", signerName, err)
	}

	cryptoSigner, err := ctx.cryptoCtx.FindKeyPair(nil, []byte(signerName))
	if err != nil {
		ctx.ctxLock.Lock()
		defer ctx.ctxLock.Unlock()
		if err := ctx.cryptoCtx.DeleteCertificate(nil, []byte(signerName), nil); err != nil {
			ctx.log.Info("Failed remove certificate for incomplete provision", "error", err)
		}
		return nil, fmt.Errorf("failed to load the stored key: %v", err)
	}
	s.SetReady(cryptoSigner, cert)

	if err := selfca.ValidateCACertificate(cert, cryptoSigner.Public()); err != nil {
		if removeError := ctx.removeSignerInToken(s); removeError != nil {
			ctx.log.V(2).Error(removeError, "failed to remove signer due to invalid CA certificate", "signer", signerName)
		}
		s.SetError(err)
		return nil, fmt.Errorf("CA certificate validation failure: %v", err)
	}

	ctx.signers.Add(s)
	ctx.log.Info("Signer is ready", "signerName", s.Name())

	return s, err
}

func (ctx *SgxContext) provisionCertificate(signerName string, cert *x509.Certificate) error {
	certID, err := generateKeyID(rand.Reader, 16)
	if err != nil {
		return fmt.Errorf("failed to generate cert-id: %v", err)
	}
	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()

	return ctx.cryptoCtx.ImportCertificateWithLabel(certID, []byte(signerName), cert)
}

// This method should be called on reply getting from key-manager
// after successful quote validation.
func (ctx *SgxContext) provisionKey(signerName string, wrappedSWK []byte, wrappedKey []byte) ([]byte, error) {
	keyID, err := generateKeyID(rand.Reader, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key-id: %v", err)
	}

	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()

	quoteInfo, ok := ctx.quotes[signerName]
	if !ok || quoteInfo == nil {
		return nil, fmt.Errorf("quote information not found for '%s'", signerName)
	}

	pCtx := ctx.p11Ctx
	attributeSWK := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}
	rsaPkcsOaepMech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, nil))
	swkHandle, err := pCtx.UnwrapKey(ctx.p11Session, []*pkcs11.Mechanism{rsaPkcsOaepMech}, quoteInfo.prvKeyHandle, wrappedSWK, attributeSWK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap symmetric key: %v", err)
	}

	defer func() {
		pCtx.DestroyObject(ctx.p11Session, swkHandle) // nolint: errcheck
		// Once after unwrapping destroy quote info for this signer.
		// The quote key objects get deleted by the CTK.
		delete(ctx.quotes, signerName)
	}()

	ctx.log.Info("Unwrapped SWK Key successfully")

	attributeWPK := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, signerName),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}
	var mechanism uint
	var params interface{}
	if ctx.cfg.KeyWrapMechanism == config.KeyWrapAesGCM {
		// First 12 bytes are the nonce used for key encryption
		gcmStandardNonceSize := 12
		ivData := wrappedKey[:gcmStandardNonceSize]
		wrappedKey = wrappedKey[gcmStandardNonceSize:]
		mechanism = pkcs11.CKM_AES_GCM
		params = pkcs11.NewGCMParams(ivData, nil, 128)
	} else {
		mechanism = pkcs11.CKM_AES_KEY_WRAP_PAD
		params = nil
	}
	aesKeyWrapMech := pkcs11.NewMechanism(mechanism, params)

	prvKey, err := pCtx.UnwrapKey(ctx.p11Session, []*pkcs11.Mechanism{aesKeyWrapMech}, swkHandle, wrappedKey, attributeWPK)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap private key: %v", err)
	}
	ctx.log.Info("Unwrapped PWK Key successfully")

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	publicKeyAttrs, err := ctx.p11Ctx.GetAttributeValue(ctx.p11Session, prvKey, template)
	if err != nil {
		pCtx.DestroyObject(ctx.p11Session, prvKey) // nolint: errcheck
		return nil, fmt.Errorf("failed to fetch public attributes: %v", err)
	}

	publicKeyAttrs = append(publicKeyAttrs, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, signerName),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}...)

	if _, err := ctx.p11Ctx.CreateObject(ctx.p11Session, publicKeyAttrs); err != nil {
		pCtx.DestroyObject(ctx.p11Session, prvKey) // nolint: errcheck
		return nil, fmt.Errorf("failed to add public key object: %v", err)
	}

	ctx.log.Info("Unwrapped Public Key successfully")

	return keyID, nil
}

func (ctx *SgxContext) destroyP11Context() {
	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()
	if ctx.p11Ctx != nil {
		ctx.p11Ctx.Logout(ctx.p11Session)       // nolint: errcheck
		ctx.p11Ctx.CloseSession(ctx.p11Session) // nolint: errcheck
		ctx.p11Ctx.Destroy()                    // nolint: errcheck
		ctx.p11Ctx = nil
	}
}

func (ctx *SgxContext) destroyCryptoContext() {
	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()
	if ctx.cryptoCtx != nil {
		ctx.cryptoCtx.Close()
		ctx.cryptoCtx = nil
	}
}

func (ctx *SgxContext) reloadCryptoContext() error {
	ctx.destroyCryptoContext()

	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()

	cryptoCtx, err := crypto11.Configure(&crypto11.Config{
		Path:       SgxLibrary,
		TokenLabel: ctx.cfg.HSMConfig.TokenLabel,
		Pin:        ctx.cfg.HSMConfig.UserPin,
	})
	if err != nil {
		return err
	}
	ctx.cryptoCtx = cryptoCtx
	return nil
}

func (ctx *SgxContext) initializeToken() error {
	cmd := exec.Command("pkcs11-tool", "--module", SgxLibrary, "--init-token",
		"--init-pin", "--slot-index", fmt.Sprintf("%d", 0), "--label", ctx.cfg.HSMConfig.TokenLabel,
		"--pin", ctx.cfg.HSMConfig.UserPin, "--so-pin", ctx.cfg.HSMConfig.SoPin)

	if output, err := cmd.CombinedOutput(); err != nil {
		ctx.log.Info("Failed token initialize", "command", cmd.Args, "output", output)
		return fmt.Errorf("failed to initialize token: %v", err)
	}

	return ctx.reloadCryptoContext()
}

func (ctx *SgxContext) initializeSigner(s *signer.Signer) (err error) {
	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()

	defer func() {
		if err != nil {
			s.SetError(err)
		}
	}()

	reader, err := ctx.cryptoCtx.NewRandomReader()
	if err != nil {
		return fmt.Errorf("failed to initialize random reader: %v", err)
	}

	keyID, err := generateKeyID(reader, 32)
	if err != nil {
		return err
	}

	certID, err := generateKeyID(reader, 32)
	if err != nil {
		return err
	}

	dc, err := ctx.cryptoCtx.GenerateRSAKeyPairWithLabel(keyID, []byte(s.Name()), RSAKeySize)
	if err != nil {
		return err
	}

	caCert, err := newCACertificate(dc)
	if err != nil {
		// cleanup previously created key
		dc.Delete() // nolint: errcheck
		return fmt.Errorf("failed to create CA certificate for '%s' signer: %v", s.Name(), err)
	}

	if err := ctx.cryptoCtx.ImportCertificateWithLabel(certID, []byte(s.Name()), caCert); err != nil {
		// cleanup previously created key
		dc.Delete() // nolint: errcheck
		return err
	}

	s.SetReady(dc, caCert)
	ctx.log.Info("Crypto Keypair generated", "for", s.Name())
	return nil
}

func (ctx *SgxContext) ensureQuote(signerName string) (*keyprovider.QuoteInfo, error) {
	ctx.ctxLock.Lock()
	defer ctx.ctxLock.Unlock()

	if info, ok := ctx.quotes[signerName]; ok {
		return info.QuoteInfo, nil
	}
	ctx.log.Info("Generating quote keypair...", "forSigner", signerName)
	pubHandle, privHandle, err := generateP11KeyPair(ctx.p11Ctx, ctx.p11Session)
	if err != nil {
		return nil, err
	}

	ctx.log.Info("Generating Quote...")
	quote, nonce, pubKey, err := ctx.generateQuote(pubHandle)
	if err != nil {
		ctx.p11Ctx.DestroyObject(ctx.p11Session, pubHandle)  // nolint: errcheck
		ctx.p11Ctx.DestroyObject(ctx.p11Session, privHandle) // nolint: errcheck
		return nil, err
	}
	info := &quoteInfo{
		QuoteInfo: &keyprovider.QuoteInfo{
			Quote:     quote,
			Nonce:     nonce,
			PublicKey: pubKey,
		},
		prvKeyHandle: privHandle,
		pubKeyHandle: pubHandle,
	}
	ctx.quotes[signerName] = info
	return info.QuoteInfo, nil
}

func (ctx *SgxContext) generateQuote(pubKey pkcs11.ObjectHandle) ([]byte, []byte, *rsa.PublicKey, error) {
	quoteParams := C.CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS{
		qlPolicy: C.SGX_QL_PERSISTENT,
	}

	if ctx.cfg.RandomNonce {
		// KMRA 2.2+ expects nonce in the below format:
		// --------------------------------------
		// | 28 random bytes | 4 byte timestamp |
		// --------------------------------------
		reader, err := ctx.cryptoCtx.NewRandomReader()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize random reader: %v", err)
		}
		randBytes, err := generateKeyID(reader, C.NONCE_LENGTH-4)
		if err != nil {
			return nil, nil, nil, err
		}
		now := uint32(time.Now().Unix())
		timestamp := (*[4]byte)(unsafe.Pointer(&now))[:]
		nonce := append(randBytes, timestamp...)
		for i := 0; i < C.NONCE_LENGTH; i++ {
			quoteParams.nonce[i] = C.CK_BYTE(nonce[i])
		}
	} else {
		for i := 0; i < C.NONCE_LENGTH; i++ {
			quoteParams.nonce[i] = C.CK_BYTE(i)
		}
	}
	nonce := C.GoBytes(unsafe.Pointer(&quoteParams.nonce[0]), C.NONCE_LENGTH)

	params := C.GoBytes(unsafe.Pointer(&quoteParams), C.int(unsafe.Sizeof(quoteParams)))
	m := pkcs11.NewMechanism(C.CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY, params)

	quotePubKey, err := ctx.p11Ctx.WrapKey(ctx.p11Session, []*pkcs11.Mechanism{m}, pkcs11.ObjectHandle(0), pubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	offset := sgxutils.QuoteOffset(quotePubKey)
	if offset <= 0 || offset >= uint64(len(quotePubKey)) {
		return nil, nil, nil, fmt.Errorf("quote generation failure: invalid quote")
	}

	publicKey, err := sgxutils.ParseQuotePublickey(quotePubKey[:offset])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse quote public key: %v", err)
	}

	return quotePubKey[offset:], nonce, publicKey, nil
}

func initP11Session(p11Ctx *pkcs11.Ctx, tokenLabel, userPin, soPin string) (pkcs11.SessionHandle, error) {
	slot, err := findP11Slot(p11Ctx, tokenLabel)
	if err != nil {
		return 0, err
	}

	p11Session, err := p11Ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: failed to open session: %v", err)
	}
	return p11Session, nil
}

func findP11Slot(p11Ctx *pkcs11.Ctx, tokenLabel string) (uint, error) {
	list, err := p11Ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: failed to get slot list: %v", err)
	}
	if len(list) == 0 {
		return 0, fmt.Errorf("pkcs11: no slots available")
	}

	for _, slot := range list {
		tInfo, err := p11Ctx.GetTokenInfo(slot)
		if err != nil {
			return 0, fmt.Errorf("pkcs11: failed to get token info(%d): %v", slot, err)
		}

		if tInfo.Label == tokenLabel {
			return slot, nil
		}
	}

	return 0, fmt.Errorf("token %v", keyprovider.ErrNotFound)
}

func generateP11KeyPair(p11Ctx *pkcs11.Ctx, p11Session pkcs11.SessionHandle) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	keyID, err := generateKeyID(rand.Reader, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to generate key-id: %v", err)
	}

	public := crypto11.AttributeSet{}
	public.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, RSAKeySize),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, EnclaveQuoteKeyObjectLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	})

	private := crypto11.AttributeSet{}
	private.AddIfNotPresent([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	})

	// Generate a keypair used to generate and exchange SGX enclabe quote
	return p11Ctx.GenerateKeyPair(p11Session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
	}, public.ToSlice(), private.ToSlice())
}

func generateKeyID(reader io.Reader, len uint) ([]byte, error) {
	keyID := make([]byte, len)
	if _, err := reader.Read(keyID); err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %v", err)
	}

	return keyID, nil
}

// newCACertificate returns a self-signed certificate used as certificate authority
func newCACertificate(key crypto.Signer) (*x509.Certificate, error) {
	max := new(big.Int).SetInt64(math.MaxInt64)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Version:               tls.VersionTLS12,
		SerialNumber:          serial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		Subject: pkix.Name{
			CommonName:   "SGX self-signed root certificate authority",
			Organization: []string{"Intel(R) Corporation"},
		},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	*tmpl = x509.Certificate{}
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	runtime.SetFinalizer(cert, func(c *x509.Certificate) {
		*c = x509.Certificate{}
	})

	return cert, nil
}
