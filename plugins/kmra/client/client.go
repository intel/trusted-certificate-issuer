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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type httpClient interface {
	get(url string) ([]byte, error)
	post(url string, request []byte) ([]byte, error)
}

type kmClient struct {
	client *http.Client
}

func newHttpClient(caCertPath, clientCertPath, clientKeyPath string, timeout time.Duration) (httpClient, error) {
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed creating x509 keypair: %v", err)
	}
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening ca cert `%s`, error: %v", caCert, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	return &kmClient{&http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (c *kmClient) get(url string) ([]byte, error) {
	response, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error received on http get request: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read http get response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get request returned status %d (%s): %s", response.StatusCode, response.Status, string(responseBody))
	}
	return responseBody, nil
}

func (c *kmClient) post(url string, request []byte) ([]byte, error) {
	requestBuffer := bytes.NewBuffer(request)
	response, err := c.client.Post(url, "application/json", requestBuffer)
	if err != nil {
		return nil, fmt.Errorf("error received on http post request: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read http post response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post request returned status %d (%s): %s", response.StatusCode, response.Status, string(responseBody))
	}
	return responseBody, nil
}
