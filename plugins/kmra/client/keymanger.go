/*
Copyright 2021-2022.
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

package client

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/klog/v2/klogr"
)

const (
	defaultClientCert = "/opt/intel/ca/ctk_loadkey.crt"
	defaultClientKey  = "/opt/intel/ca/ctk_loadkey.key"
	defaultCaCert     = "/opt/intel/ca/ca.crt"
	defaultKMHost     = "localhost:5000"
	defaultTimeout    = 10 // 10s

	minApiVersionMajor = 0
	minApiVersionMinor = 2
)

type Config struct {
	ClientCert string
	ClientKey  string
	CaCert     string
	KMHost     string // Host for key management service in form <host>:<port>
	Timeout    time.Duration
}

type rsaKeyData struct {
	ExponentLen int    `json:"ExponentLen"`
	Exponent    string `json:"Exponent"`
	ModulusLen  int    `json:"ModulusLen"`
	Modulus     string `json:"Modulus"`
}

type sgxObject struct {
	RsaPublicKey *rsaKeyData `json:"RsaPublicKey"`
	SgxQuote     string      `json:"SgxQuote"`
}

type hsmObject struct {
	UniqueID string `json:"h_unique_id"`
}

type keysRequest struct {
	HsmObject *hsmObject `json:"HsmObject"`
	SgxObject *sgxObject `json:"SgxObject"`
}

type attestationResponse struct {
	Verified bool `json:"verified"`
}

type keysExportResponse struct {
	WrappedSWK  string `json:"wrappedSWK"`
	WrappedKey  string `json:"wrappedKey"`
	Certificate []byte `json:"certificate"`
}

type sysVersionResponse struct {
	ApiVersion string `json:"api_version"`
	Version    string `json:"version"`
}

type KmStore struct {
	config *Config
	log    logr.Logger
	client httpClient
}

func NewKmStore(config *Config) (*KmStore, error) {
	if config == nil {
		// create new empty config
		config = &Config{}
	}
	// set default values for not provided parameters
	config.setDefaults()

	km := &KmStore{
		log:    klogr.New().WithName("kmra"),
		config: config,
	}
	if err := km.initialize(); err != nil {
		return nil, err
	}
	return km, nil
}

// setDefaults sets the default values for missing parameters
func (c *Config) setDefaults() {
	if c.ClientCert == "" {
		c.ClientCert = defaultClientCert
	}
	if c.ClientKey == "" {
		c.ClientKey = defaultClientKey
	}
	if c.CaCert == "" {
		c.CaCert = defaultCaCert
	}
	if c.KMHost == "" {
		c.KMHost = defaultKMHost
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout * time.Second
	}
}

func (km *KmStore) initialize() error {
	if km == nil {
		return errors.New("kmStore is nil")
	}
	// Create new http client to send requests to keys server
	client, err := newHttpClient(km.config.CaCert, km.config.ClientCert, km.config.ClientKey, km.config.Timeout)
	if err != nil {
		return err
	}
	km.client = client

	// Get the server API version
	version, err := km.getApiVersion()
	if err != nil {
		return err
	}
	// Check if api version meets criteria
	err = validateMinApiVersion(version)
	if err != nil {
		return fmt.Errorf("server api version validation failed: %v", err)
	}

	return nil
}

func (km *KmStore) GetCAKeyAndCertificate(signerName string, quote []byte, publicKey []byte) ([]byte, []byte, error) {
	if km == nil {
		return nil, nil, errors.New("kmStore is nil")
	}
	return km.keysExport(signerName, quote, publicKey)
}

// ValidateQuote uses post request to attest the quote match the key for a given signer
func (km *KmStore) ValidateQuote(signerName string, quote []byte, publicKey []byte) (bool, error) {
	if km.client == nil {
		return false, errors.New("http client is not initialized")
	}
	attestationUrl := fmt.Sprintf("https://%s/sgx/attest", km.config.KMHost)

	requestBody, err := buildKeysRequest(signerName, quote, publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to create attestation request: %v", err)
	}

	km.log.Info("Sending post request", "url", attestationUrl, "request", string(requestBody))
	response, err := km.client.post(attestationUrl, requestBody)
	if err != nil {
		return false, fmt.Errorf("post request for attestation failed: %v", err)
	}

	var result attestationResponse
	err = json.Unmarshal(response, &result)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal attestation response: %v", err)
	}
	return result.Verified, nil
}

// keysExport uses post request to get the wrapped keys and certificate from server
func (km *KmStore) keysExport(signerName string, quote []byte, publicKey []byte) ([]byte, []byte, error) {
	if km.client == nil {
		return nil, nil, errors.New("http client is not initialized")
	}
	keysServiceUrl := fmt.Sprintf("https://%s/sgx/keys/export", km.config.KMHost)

	requestBody, err := buildKeysRequest(signerName, quote, publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create keys request: %v", err)
	}

	km.log.Info("Sending post request", "url", keysServiceUrl, "request", string(requestBody))
	response, err := km.client.post(keysServiceUrl, requestBody)
	if err != nil {
		return nil, nil, fmt.Errorf("post request for keys failed: %v", err)
	}

	var returnedKeys keysExportResponse
	err = json.Unmarshal(response, &returnedKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal sgx keys response: %v", err)
	}
	// Encode wrapped keys into single base64 encoded block
	wrappedKeys, err := encodeWrappedKeys(&returnedKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode wrapped keys: %v", err)
	}

	return wrappedKeys, []byte(base64.StdEncoding.EncodeToString(returnedKeys.Certificate)), nil
}

// getApiVersion uses get request to get the server version and api version.
// On success only the api version is returned.
func (km *KmStore) getApiVersion() (string, error) {
	if km.client == nil {
		return "", errors.New("http client is not initialized")
	}
	versionUrl := fmt.Sprintf("https://%s/sys/version", km.config.KMHost)
	km.log.Info("Sending get request", "url", versionUrl)
	response, err := km.client.get(versionUrl)
	if err != nil {
		return "", fmt.Errorf("failed to get sys version from server: %v", err)
	}

	var versions sysVersionResponse
	err = json.Unmarshal(response, &versions)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal sys version response: %v", err)
	}
	km.log.Info("server version response", "version", versions.Version, "apiVersion", versions.ApiVersion)
	return versions.ApiVersion, nil
}

// validateMinApiVersion checks that provided version is bigger or equal to minimal requirements
func validateMinApiVersion(version string) error {
	// Expected format is major.minor
	versionSlice := strings.Split(version, ".")
	if len(versionSlice) != 2 {
		return errors.New("wrong api version format, expected is major.minor")
	}
	major, err := strconv.Atoi(versionSlice[0])
	if err != nil {
		return err
	}
	minor, err := strconv.Atoi(versionSlice[1])
	if err != nil {
		return err
	}
	if (major < minApiVersionMajor) || (major == minApiVersionMajor && minor < minApiVersionMinor) {
		return fmt.Errorf("minimum api version is %d.%d, get version returned %s", minApiVersionMajor, minApiVersionMinor, version)
	}

	return nil
}

// buildKeysRequest parses the provided key and creates request in json format
// corresponding to AppHSM REST API.
func buildKeysRequest(signerName string, quote []byte, publicKey []byte) ([]byte, error) {
	// Get the exponent and modulus from public key
	decodedKey, _ := pem.Decode(publicKey)
	if decodedKey == nil {
		return nil, errors.New("publicKey is not a correct PEM data")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(decodedKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaPublicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to assert type of publicKey, invalid format")
	}
	exponent := big.NewInt(int64(rsaPublicKey.E))
	modulus := rsaPublicKey.N

	keyData := rsaKeyData{
		ExponentLen: len(exponent.Bytes()),
		Exponent:    base64.StdEncoding.EncodeToString(exponent.Bytes()),
		ModulusLen:  len(modulus.Bytes()),
		Modulus:     base64.StdEncoding.EncodeToString(modulus.Bytes()),
	}
	sgxData := sgxObject{
		RsaPublicKey: &keyData,
		SgxQuote:     string(quote),
	}
	hsmData := hsmObject{
		UniqueID: signerName,
	}
	requestData := &keysRequest{
		HsmObject: &hsmData,
		SgxObject: &sgxData,
	}
	requestBody, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json with request data: %v", err)
	}
	return requestBody, nil
}

func encodeWrappedKeys(keys *keysExportResponse) ([]byte, error) {
	// Decode the key and swk
	rawSWK, err := base64.StdEncoding.DecodeString(keys.WrappedSWK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode wrapped swk: %v", err)
	}
	rawKey, err := base64.StdEncoding.DecodeString(keys.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode wrapped key: %v", err)
	}
	// Encode the key and swk back into single block of data
	buff := bytes.Buffer{}
	encoder := base64.NewEncoder(base64.StdEncoding, &buff)
	_, err = encoder.Write(rawSWK)
	if err != nil {
		return nil, err
	}
	_, err = encoder.Write(rawKey)
	if err != nil {
		return nil, err
	}
	// Close to flush any remaining data to buffer
	err = encoder.Close()
	if err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}
