# Trusted Certificate Service for Kubernetes Platform
<!-- Table of contents is auto generated using 
[Auto Markdown TOC](https://marketplace.visualstudio.com/items?itemName=huntertran.auto-markdown-toc) extension -->
<!-- TOC depthfrom:2 depthto:3 -->

- [Overview](#overview)
- [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Create an Issuer](#create-an-issuer)
    - [Create certificates](#create-certificates)
- [Sample use cases](#sample-use-cases)

<!-- /TOC -->

## Overview

<!-- TODO: Review and rephrase this section -->
Trusted Certificate Service (TCS) is a Kubernetes certificate signing solution that uses the security capabilities provided by the Intel® SGX. The signing key is stored and used inside the SGX enclave(s) and is never stored in clear anywhere in the system. TCS is implemented as a [cert-manager external issuer](https://cert-manager.io/docs/configuration/external/) by providing support for both cert-manager and kubernetes certificate siging APIs.

## Getting started

All the examples in this page are using self-signed CA certificates. If you are looking for more advanced use cases (e.g., Istio integration) please check the [sample use cases](#sample-use-cases).

### Prerequisites

Prerequisites for building and running Trusted Certificate Service:

- Kubernetes cluster with one or more nodes with Intel® [SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html) supported hardware
- [Intel® SGX device plugin](https://github.com/intel/intel-device-plugins-for-kubernetes/blob/main/cmd/sgx_plugin/README.md) for Kubernetes
- [Intel® SGX AESM daemon](https://github.com/intel/linux-sgx#install-the-intelr-sgx-psw)
- [cert-manager](https://cert-manager.io/next-docs/installation/). The `cmtool` is also used later in the examples so you may want to install it also.
- Linux kernel version 5.11 or later on the host (in tree SGX driver)
- git, or similar tool, to obtain the source code
- Docker, or similar tool, to build container images
- Container registry ([local](https://docs.docker.com/registry/deploying/) or remote)

### Installation

This section covers how to obtain the source code, build and install it.

1. Getting the source code

```sh
git clone https://github.com/intel/trusted-certificate-issuer.git
```
2. Build and push the container image

Choose a container registry to push the generated image using `REGISTRY` make variable.
The registry should be reachable from the Kubernetes cluster.

```sh
$ cd trusted-certificate-issuer
$ export REGISTRY="localhost:5000" # docker registry to push the container image
$ make docker-build
$ make docker-push
```

3. Deploy custom resource definitions (CRDs)

```sh
# set the KUBECONFIG based on your configuration
export KUBECONFIG="$HOME/.kube/config"
make install # Install CRDs
```

4. Make the deployment

```sh
make deploy
```

By default, `tcs-issuer` namespace is used for the deployment.
```sh
# Ensure that the pod is running state
$ kubectl get po -n tcs-issuer
NAME                              READY   STATUS    RESTARTS   AGE
tcs-controller-5dd5c46b44-4nz9f   1/1     Running   0          30m
```

### Create an Issuer

Once the deployment is up and running, you are ready to provision TCS
issuer(s) using either a namespace-scoped `TCIssuer` or a
cluster-scoped `TCSClusterIssuer` resource.

The example below creates a TCS issuer named `my-ca` for `sandbox` namespace:

```sh
kubectl create ns sandbox
cat <<EOF |kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSIssuer
metadata:
    name: my-ca
    namespace: sandbox
spec:
    secretName: my-ca-cert
EOF
```

Successful deployment looks like this:

```sh
$ kubectl get tcsissuers -n sandbox
NAME    AGE    READY   REASON      MESSAGE
my-ca   2m     True    Reconcile   Success

$ kubectl get secret my-ca-cert -n sandbox
NAME                  TYPE                                  DATA   AGE
my-ca-cert            kubernetes.io/tls                     2      3h14m
```

The above issuer creates and stores it's private key inside the
SGX enclave and the root certificate is saved as Kubernetes Secret with name
specified with `spec.secretName`, under the issuer's namespace.

Typically the issuer secret (`my-ca-cert` in our case) contains both the certificate and the private key. But in Trusted Certificate Service case, the private key is empty since they key is stored and used inside the SGX enclave. You can verify the empty private key in the secret with the following command:

```sh
kubectl get secrets -n sandbox my-ca-cert -o jsonpath='{.data.tls\.key}'
```

### Create certificates

Creating and signing certificates can be done by using cert-manager `Certificate` or Kubernetes `CertificateSigningRequest` APIs.

#### Using cert-manager Certificate

This example shows how to request X509 certificate signed by the Trusted Certificate Service
using cert-manger `Certificate` API. Create a cert-manager `Certificate` object and
set the `spec.issuerRef` to `TCSIssuer`(or `TCSClusterIssuer`).

```sh
cat <<EOF |kubectl create -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-certificate
  namespace: sandbox
spec:
  # The secret name to store the signed certificate
  secretName: demo-cert-tls
  # Common Name
  commonName: intel.sgx.demo
  # Ensure the issuerRef is set to the right issuer
  issuerRef:
    group: tcs.intel.com # TCS issuer API group
    kind: TCSIssuer      # Configured issuer type
    name: my-ca          # Configured issuer name
EOF
```

The cert-manager creates a corresponding `CertificateRequest` for the
`Certificate` above. One has to approve the `CertificateRequest` so that
the TCS controller can sign the request in the next reconcile loop.

```sh
$ kubectl get certificaterequest -n sandbox
NAME                   APPROVED   DENIED   READY   ISSUER   REQUESTOR                                         AGE
my-certificate-nljcz   False               False   my-ca    system:serviceaccount:cert-manager:cert-manager   1m
```

Privileged user needs to approve the `CertificateRequest` with the cert-manager's `cmctl` utility:

```sh
$ cmctl approve my-certificate-nljcz -n sandbox
```

Check if the certificate is exported to the secret referenced in
the `spec.secretName`.

```sh
$ kubectl get certificates,secret -n sandbox
NAME                                         READY   SECRET          AGE
certificate.cert-manager.io/my-certificate   True    demo-cert-tls   2m1s

NAME                         TYPE                                  DATA   AGE
secret/default-token-69dv6   kubernetes.io/service-account-token   3      3h15m
secret/demo-cert-tls         kubernetes.io/tls                     2      2m1s
secret/my-ca-cert            kubernetes.io/tls                     2      3h14m
```

#### Using Kubernetes CSR

This example shows how to request an X509 certificate signed by the Trusted Certificate Service
using Kubernetes CSR.

First, generate a PEM encoded private key (`privkey.pem`) and certificate signing request (`csr.pem`)
using `openssl` tool:

```sh
$ openssl req -new -nodes -newkey rsa:3072 -keyout privkey.pem -out ./csr.pem -subj "/O=Foo Company/CN=foo.bar.com"
```

Create a Kubernetes `CertificateSigningRequest` using the csr (`csr.pem`) generated above.
The `spec.signerName` field must refer to the TCS issuer we configured earlier
in the form of `<issuer-type>.<issuer-group>/<issuer-namespace>.<issuer-name>`.
In this example the signer name is `tcsissuer.tcs.intel.com/sandbox.my-ca`.

**Note:** the issuer namespace in the case of `tcsclusterissuer` is the namespace
of the Trusted Certificate Service. 

```sh
cat <<EOF |kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: test-csr
spec:
  groups:
  - system:authenticated
  request: $(cat csr.pem | base64 | tr -d '\n')
  signerName: tcsissuer.tcs.intel.com/sandbox.my-ca
  usages:
  - client auth
EOF
```

Now the `test-csr` is the in pending state waiting for approval.

```sh
$ kubectl get certificatesigningrequests
NAME       AGE   SIGNERNAME                              REQUESTOR          CONDITION
test-csr   46s   tcsissuer.tcs.intel.com/sandbox.my-ca   kubernetes-admin   Pending
````

Privileged user needs to approve the `test-csr` with the following command:

```sh
# Approve the CSR so the TCS controller generates the certificate
kubectl certificate approve test-csr
```
Once the request is approved Trusted Certificate Service signs it. At this point the CSR contains the requested certificate signed by the CA using the private key stored inside the SGX enclave.

You can examine the CSR with the following command:

```sh
$ kubectl describe csr

Name:         test-csr
Labels:       <none>
Annotations:  kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"certificates.k8s.io/v1","kind":"CertificateSigningRequest","metadata":{"annotations":{},"name":"test-csr"},"spec":{"groups":["system:authenticated"],"request":"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJRGNUQ0NBZGtDQVFBd0xERVVNQklHQTFVRUNnd0xSbTl2SUVOdmJXRndibmt4RkRBU0JnTlZCQU1NQzJadgpieTVpWVhJdVkyOXRNSUlCb2pBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVk4QU1JSUJpZ0tDQVlFQTZhNzkvTmZLCmdrYzQ5dXd6TVFUajBwZzhuZjZ3VU5tcmNVaG5IUDNhUitDYjZKcE0wOVF3RHBmblI2VU13ejZFVy9RSis3WVQKMndLUFJTRVZqZ3owT29NdXh0c0tScGN2VCtWaDZkb3JjSkU0ZTdjQ2FWK1ZKN0pQRGtwYzdFNSt6VCtncVlRKwptMWhjS0FmTEk0VEpZNzJZR2MzTWt5QkVqRzNsKzl3emxHNVlpZEduYVFjNDhMNUJQSXFxOEdKelpWSTkvQWxLClVDVjcwM2pGQnpKdTBEbFpTQWd2WEo1RUhNbWVhaFBQYTFOV2dkM29mQ2FUcTlnM0xaSTBDejdWbndOK0l1bzEKNGpRcE1zNzVQTFZVUTQ2SEZ0YUxJTWZPNDlkZk94SUwwNlkwZG1XNUc0R05zNUR4SkhtYm11QlQ1NGMrUm5MUQoyVldJL2VRS2xQQW5Sdk00SmpEM3hEcENvOGViSE9nS2RsRU9MTkFPTEk0L2VMUG1GcXlTUGxuY2RTZlFqc2UvCkJQOEpuQk9Xa0xpSUZ4bzBwT1lrTUFDaHhWdDJkdURLcldRZm1JSkhUUSs0Q05OZjhlanZOZkZCY0pmNllldHUKRnlkNnA4WmwrYkV2TldYbDBKeGNQNWlFVGFYWkZqblJqMWxzZWVSbWo3OGFyRDZCUkhTTFlsM0pBZ01CQUFHZwpBREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBWUVBMXYrOURlUE5XOER6Z2twVzBhU1czdW1xR05xc05zaWNhQjc1Cjc3UGsyRnNBMTMya2JWTXBBY2NCRzc1WGh4T0VkNFNYdTJ0eVI1MGxOMUpaNnJldzY5b1dUYWZTTTVXNm00RFAKcE1tVjRJbTJiajlUTUhYeHdXVjdXVk5JL2dQK1BFRDVROVJMNy82Sjh2VnV5aFhZaTAyc2NkampKaStIT0M4Ywo1TFpLem5TQUhtcmZEVGlveG5ydUNqY1ZEZlFlSGlJMkw1SW94aXAwUmt5L0Y1UkhwTjRyMHFQS25Na2F3enRYClV3alB6Nk9uWGVPK1EvVGZyRm5ka2V3OCtsSFc2akxneXNUNlU3SjdmdjVuL1lSUXdYSHJadi9LNFVneW9zU3oKZy9PSkZoOVpyWjl6WFBhT01sN1pLYnlUUXE2NGtMSmFEQys0eWIycXlUT1hMUm1xK0Y1MWc2a0tJdDdMWXdtMQpjR0N3WTc2WmFHMm9hVkQxRVNQSWtpc0I4U01ncVNEajlhQjFxRDJ0Y1E4RGxoV1o3dEdDd3M5VC9RUDlvQnpsCjc5S0g3Qnc1QnVSVFlRT0srMTdJSWUrNUx0YVFzS1dpczBsaGtvQ1R3TjdUS2FnQ1dLWWk0RE16em1wVlNvbTEKaVphb21nUDJIKy8yQ3RoOUNJN1dwVWR5WklkQgotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K","signerName":"tcsissuer.tcs.intel.com/sandbox.my-ca","usages":["client auth"]}}

CreationTimestamp:  Mon, 24 Jan 2022 16:11:10 +0200
Requesting User:    kubernetes-admin
Signer:             tcsissuer.tcs.intel.com/sandbox.my-ca
Status:             Approved,Issued
Subject:
         Common Name:    foo.bar.com
         Serial Number:  
         Organization:   Foo Company
```

## Sample use cases

Refer to more example use cases related to Istio service mesh and Trusted Certificate Service

- [Istio custom CA integration using Kubernetes CSR](./docs/istio-custom-ca-with-csr.md)
- [Istio integration with cert-manager and istio-csr](./docs/istio-csr-external-ca-setup.md)
- [Remote attestation and key management (manual)](./docs/integrate-key-server.md)
# Limitations

- This version of the software is pre-production release and is meant for evaluation and trial purposes only.
- The certificate authority (CA) private key transport method (via QuoteAttestation custom resource) does not guarantee any authenticity, only confidentiality, and therefore cannot protect from attacks like key substitution or key replay.
