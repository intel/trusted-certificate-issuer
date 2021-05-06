# Istio integration with cert-manager istio-csr
-------------------------------------------------------------

cert-manager supports [istio-csr](https://github.com/cert-manager/istio-csr/blob/main/docs/getting_started.md)
which is an agent that allows for Istio workload and control plane components to be secured.
This example shows how to provision Istio workload
certificates using an Issuer provided by the Trusted Certificate Service (TCS).


## Prerequisites for running this example:

  - istioctl
  - Kubernetes cluster with at least one Intel SGX enabled node
  - cert-manager
  
## Deployment

Deploy TCS and custom resource definitions (CRDs).

```sh
kubectl apply -f deployment/crds/
kubectl apply -f deployment/tcs_issuer.yaml
```

Create a TCS Issuer that could sign certificates for `istio-system` namespace

```sh
cat << EOF | kubectl create -f -
cat <<EOF |kubectl create -f -
apiVersion: tcs.intel.com/v1alpha1
kind: TCSIssuer
metadata:
    name: sgx-ca
    namespace: istio-system
spec:
    secretName: istio-ca
EOF
```

Update the cert-manager RBAC rules to auto approve the `CertificateRequests` for
TCS issuers (`tcsissuer` and `tcsclusterissuer` in `tcs.intel.com` group):

```sh
kubectl create -f deployment/cert-manager-rbac.yaml
```

Export the TCS issuer CA root certificate to `cert-manager` namespace

```sh
kubectl get -n istio-system secret istio-ca -o go-template='{{index .data "tls.crt"}}' | base64 -d > ca.pem
kubectl create secret generic -n cert-manager istio-root-ca --from-file=ca.pem=ca.pem
```

Deploy Istio-CSR with appropriate values:

```sh
helm repo add jetstack https://charts.jetstack.io
helm repo update  
helm install -n cert-manager cert-manager-istio-csr jetstack/cert-manager-istio-csr \
--set "app.tls.rootCAFile=/var/run/secrets/istio-csr/ca.pem" \
--set "volumeMounts[0].name=root-ca" \
--set "volumeMounts[0].mountPath=/var/run/secrets/istio-csr" \
--set "volumes[0].name=root-ca" \
--set "volumes[0].secret.secretName=istio-root-ca" \
--set "app.certmanager.issuer.name=sgx-ca" \
--set "app.certmanager.issuer.kind=TCSIssuer" \
--set "app.certmanager.issuer.group=tcs.intel.com" \
--set "app.logLevel=4"
```
Ensure the `istio-csr` deployed is running successfully

```sh
$ kubectl -n cert-manager get pod
NAME                                      READY   STATUS    RESTARTS   AGE
cert-manager-55658cdf68-5pf8z             1/1     Running   0          4m
cert-manager-cainjector-967788869-4jz9t   1/1     Running   0          4m
cert-manager-istio-csr-554b5798d8-llgtx   1/1     Running   0          4m
cert-manager-webhook-7b86bc6578-nnxpg     1/1     Running   0          4m
```

Install Istio with custom configuration:

```sh
curl -sSL https://raw.githubusercontent.com/cert-manager/istio-csr/main/docs/istio-config-getting_started.yaml > istio-install-config.yaml
istioctl install -f istio-install-config.yaml
```

Ensure the `istio` deployed is running successfully

```sh
$ kubectl get po -n istio-system
NAME                                    READY   STATUS    RESTARTS   AGE
istio-egressgateway-d5fd5f4f-6xk65      1/1     Running   0          3m
istio-ingressgateway-6cd95bd9cf-crdsx   1/1     Running   0          3m
istiod-f985cb778-bpnkc                  1/1     Running   0          3m
```

Deploy the `bookinfo` sample application as desribed in [here](istio-custom-ca-with-csr.md)
