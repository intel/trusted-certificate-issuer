#!/bin/bash

#
# Exports sgx-ca secrets to istio-system namespace
# 
SGX_CA_SECRET_NAME=sgx-ca-signer
SGX_CA_SECRET_NS=sgx-operator
ISTIOD_EXTERNAL_CA_SECRET_NAME=external-ca-cert
ISTIOD_EXTERNAL_CA_SECRET_NS=istio-system

# First create target namespace
kubectl create namespace ${ISTIOD_EXTERNAL_CA_SECRET_NS} || true

cat <<EOF | kubectl apply -f - 
apiVersion: v1
kind: Secret
metadata:
  name: ${ISTIOD_EXTERNAL_CA_SECRET_NAME}
  namespace: ${ISTIOD_EXTERNAL_CA_SECRET_NS}
data:
  root-cert.pem: $(kubectl get secret -n ${SGX_CA_SECRET_NS} ${SGX_CA_SECRET_NAME} -o jsonpath='{.data.tls\.crt}')
EOF
