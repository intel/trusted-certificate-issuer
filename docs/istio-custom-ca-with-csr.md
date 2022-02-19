# Istio integration with custom CA using Kubernetes CSR

Istio supports [integrating custom certificate authority(CA) using Kubernetes CSR](https://istio.io/latest/docs/tasks/security/cert-management/custom-ca-k8s/#part-2-using-custom-ca)
as an experimental feature. This example shows how to provision Istio workload
certificates using an Issuer provided by the Trusted Certificate Service (TCS).

## Prerequisites for running this example:

  - istioctl (version 1.13 or later)
  - Kubernetes cluster with at least one Intel SGX enabled node
  
## Deployment

Deploy TCS and custom resource definitions (CRDs).

```sh
kubectl apply -f deployment/crds/
kubectl apply -f deployment/tcs_issuer.yaml
```

Create a TCS Cluster Issuer that could sign certificates for Istio and service mesh workloads.

```sh
export CA_SIGNER_NAME=sgx-signer
cat << EOF | kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSClusterIssuer
metadata:
    name: $CA_SIGNER_NAME
spec:
    secretName: ${CA_SIGNER_NAME}-secret
EOF
````

You can print the CA certificate with the command below. Note: the CA private key (tls.key) is empty since it is stored inside the SGX enclave.

```sh
kubectl get secret -n tcs-issuer ${CA_SIGNER_NAME}-secret -o jsonpath='{.data.tls\.crt}' |base64 -d | sed -e 's;\(.*\);        \1;g'
```

Generate Istio deployment file (`istio-custom-ca.yaml`) with custom CA configuration as below. 

```sh
export CA_SIGNER=tcsclusterissuer.tcs.intel.com/sgx-signer
cat << EOF > istio-custom-ca.yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  components:
    pilot:
      k8s:
        env:
          - name: CERT_SIGNER_DOMAIN
            value: tcsclusterissuer.tcs.intel.com
          - name: EXTERNAL_CA
            value: ISTIOD_RA_KUBERNETES_API
          - name: PILOT_CERT_PROVIDER
            value: k8s.io/$CA_SIGNER
        overlays:
          - kind: ClusterRole
            name: istiod-clusterrole-istio-system
            patches:
              - path: rules[-1]
                value: |
                  apiGroups:
                  - certificates.k8s.io
                  resourceNames:
                  - tcsclusterissuer.tcs.intel.com/*
                  resources:
                  - signers
                  verbs:
                  - approve
  meshConfig:
    defaultConfig:
      proxyMetadata:
        PROXY_CONFIG_XDS_AGENT: "true"
        ISTIO_META_CERT_SIGNER: sgx-signer
    caCertificates:
    - pem: |
$(kubectl get secret -n tcs-issuer ${CA_SIGNER_NAME}-secret -o jsonpath='{.data.tls\.crt}' |base64 -d | sed -e 's;\(.*\);        \1;g')
      certSigners:
      - $CA_SIGNER
EOF
```

Install istio with the generated `istio-custom-ca.yaml` deployment file.


```sh
istioctl install -y -f istio-custom-ca.yaml
```

## Sample application

Once the above Istio deployment is successful deploy the `bookinfo`
sample application in bookinfo namespace.

```sh
kubectl create ns bookinfo
kubectl label ns bookinfo istio-injection=enabled
kubectl apply -n bookinfo -f https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml
```

Verify that the all the `bookinfo` sample application pods are in running state using the certificates signed by the Trusted Certificate Service (TCS).

```sh
$ kubectl get pods -n bookinfo
NAME                              READY   STATUS    RESTARTS   AGE
details-v1-67bc58d576-c74zl       2/2     Running   0          56s
productpage-v1-7565c8c459-rqmzj   2/2     Running   0          50s
ratings-v1-6485fbb4dd-hwn6n       2/2     Running   0          54s
reviews-v1-545675bc9-8knfl        2/2     Running   0          52s
reviews-v2-759759586-lpftf        2/2     Running   0          52s
reviews-v3-bb5f95b65-phmx6        2/2     Running   0          51s
```

You can monitor the certificate signing requests (CSR) being created, approved and signed with the following command:

```sh
kubectl get csr -A -w
```
