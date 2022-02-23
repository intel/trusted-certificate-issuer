
## Remote attestation and key management (manual)

Trusted Certificate Service (TCS) supports SGX remote attestation and sample key management reference application.

[Remote attestation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/attestation-services.html) is an advanced feature which allows an entity to gain relying party's trust. Remote attestation gives the relying party increased confidence that the software is running inside a SGX enclave. The attestation results includes the identity of the software being attested and an assesment of possible software tampering.

Key management enables external key management systems' to deliver the certificates and keys via secure mechanisms into the SGX enclave. 

**NOTE**: In this release we only support manual operations which are for demonstration purposes only. In the future releases will add more capabilities to the attestation and key management. 

The core mechanism to integrate the attestation and key management is a Kubernetes Custom Resource Definition (CRD) `QuoteAttestation`, which is based on [SGX ECDSA attestation](https://www.intel.com/content/www/us/en/developer/articles/technical/quote-verification-attestation-with-intel-sgx-dcap.html) defined by the [Intel® SGX Data Center Attestation Primitives](https://github.com/intel/SGXDataCenterAttestationPrimitives).

[Intel® KMRA](https://01.org/key-management-reference-application-kmra) project provides command line tools which can read, write and update the `QuoteAttestation`. The KMRA tools also do the attestation and key management based on the information from the `QuoteAttestation`.

Refer to [QuoteAttestation CRD API](./quote-attestation-api.md) for further details.

**NOTE**: The cluster admins must regulate the access to the `QuoteAttestation` resource with appropriate [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) (Role Based Access Control) rules such that no other component in the cluster can create/write/update/delete the `QuoteAttestation` object other than, the Trusted Certificate Service (`tcs-issuer` Kubernetes pod).

## Prerequisites for running this example:

  - istioctl
  - Kubernetes cluster with at least one Intel SGX enabled node
  - AESMD running on the host 

## Deployment

Deploy TCS and custom resource definitions (CRDs).

```sh
kubectl apply -f deployment/crds/
kubectl apply -f deployment/tcs_issuer.yaml
```
## Create (non-self-signed) issuer

Ensure that the `spec.selfSign` of the issuer set to `false` indicating that TCS will not create self-signed certificate but expects it to be provided via other mechanism.

```sh
kubectl create ns sandbox
cat <<EOF |kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSIssuer
metadata:
    name: external-ca
    namespace: sandbox
spec:
    secretName: external-ca-secret
    selfSign: false
EOF
```

Once the above issuer is created, the TCS creates a
 `QuoteAttestation` custom resource (CR) and waits for an
external key-management server to verify the quote and provision
the CA private key and certificate. The issuer is not ready before the quote attestation is done and CA private key and certificate are delivered.

You can verify that the `QuoteAttestation` exists:

```sh
$ kubectl get quoteattestations.tcs.intel.com -n tcs-issuer
NAME                                          AGE
sandbox.external-ca.tcsissuer.tcs.intel.com   21s
```

We use command line tools to read and write the `QuoteAttestation` manually. You get the tools, `km-attest` and `km-wrap`, provided by the [Intel® KMRA project](https://01.org/key-management-reference-application-kmra).

Once you have the tools installed, you can start the quote attestation and key management operations.

First, extract the public key and quote from the `sandbox.external-ca.tcsissuer.tcs.intel.com` CR with the following commands:

```sh
kubectl get quoteattestations.tcs.intel.com -n tcs-issuer sandbox.external-ca.tcsissuer.tcs.intel.com -o jsonpath='{.spec.publicKey}' | base64 -d > /tmp/public.key
kubectl get quoteattestations.tcs.intel.com -n tcs-issuer sandbox.external-ca.tcsissuer.tcs.intel.com -o jsonpath='{.spec.quote}' | base64 -d > /tmp/quote.data
```

The next command (`km-attest`) needs to be executed on a machine with SGX in order to succeed.
Use `km-attest` tool to do the SGX quote attestation using the public key and quote from the
previous step:

```sh
km-attest --pubkey /tmp/public.key --quote /tmp/quote.data
````

Successful attestation looks like this:

```console
Public key hash verification successful
SGX_QL_QV_RESULT_OK
Quote is correct, platform contains latest TCB.
Quote verification successful
```

In case you don't have the private key and certificate you can generate one with the following command:

```sh
openssl req -x509 -nodes -newkey rsa:4096 -keyout /tmp/ca-private.pem -out /tmp/ca-cert.pem -sha256 -days 365 -subj '/CN=SGX.intel.com'
```

The private key is next delivered to SGX enclave. The private key is encrypted with temporary AES-256 key which is in turn encrypted with the public key from the quote. The two incredients are put together to form a wrap <sup>[3]</sup>. Only the SGX enclave holding the private key can open the wrap containing the private key.

Use the `km-wrap` tool to wrap the private key and store it in `WRAPPED_KEY` environment variable:

```sh
WRAPPED_KEY=$(sudo km-wrap --pubkey /tmp/public.key --privkey /tmp/ca-private.pem --pin 123456789 --token SgxOperator --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so)
```
<sup>3</sup> [PKCS11 wrapping/unwrapping private keys](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/csprd02/pkcs11-curr-v2.40-csprd02.html#_Toc387327798)

Verify that the `WRAPPED_KEY` contains base64 encoded data and not error messages (`echo $WRAPPED_KEY`).

Next, you need to create kubernetes secret, in the correct namespace, which contains the wrapped private key and certificate:

```sh
kubectl create secret generic -n tcs-issuer wrapped-key --from-literal=tls.key=${WRAPPED_KEY} --from-literal=tls.crt=$(base64 -w 0 < /tmp/ca-cert.pem)
```

Finally, you need to update (patch) `external-ca.sandbox.tcsissuer.tcs.intel.com` CR. This step will trigger the TCS to process the updated CR, unwrap the key and store the key into SGX enclave.

```sh
kubectl proxy --port=9091 &
PROXY_PID=$!
trap 'kill "$PROXY_PID"' EXIT
#wait for proxy to open
sleep 2
curl --header "Content-Type: application/json-patch+json" --request PATCH \
--data '[{"op": "add", "path": "/status/secrets", "value": {"tcsissuer.tcs.intel.com/sandbox.external-ca": {"secretName": "wrapped-key", "secretType": "KMRA"}}}, {"op": "add", "path": "/status/conditions/-", "value": {"type": "CASecretReady", "status": "true", "reason": "AttestationControllerReconcile", "message": "Quote verification success"}}]' \
http://localhost:9091/apis/tcs.intel.com/v1alpha1/namespaces/tcs-issuer/quoteattestations/sandbox.external-ca.tcsissuer.tcs.intel.com/status
```

Once the CA key and certificate are provisioned, the TCS is ready for serving the approved
[CertificateSigningRequest](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/#create-a-certificate-signing-request-object-to-send-to-the-kubernetes-api) Kubernetes
resources. It checks if the CSR has `spec.signerName` set to `tcsissuer.tcs.intel.com/sandbox.external-ca`. If the signer name matches, the TCS signs the CSR with the private key stored inside the SGX enclave. The signed certificate is added to the `.status.certificate` of the CSR resource.
