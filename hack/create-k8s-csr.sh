#!/bin/bash

function generate_key() {
  echo "Generating private key ..."
  openssl genrsa -out $1 2048
}

function generate_csr() {
  key_file=$1
  csr_file=$2
  echo "Generating signing request ..."
  openssl req -new -key $key_file -out $csr_file -subj "/O=Foo Comapny/CN=foo.bar.com"
}

function create_k8s_csr() {
  csr=$1
  name=$2
  namespace=$3
  signer=$4

  echo "Generating K8s CSR object ..."
  set -x
  cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $name
  namespace: $namespace
spec:
  groups:
  - system:authenticated
  request: $(cat $csr | base64 | tr -d '\n')
  signerName: $signer
  usages:
  - client auth
EOF
}

function Usage() {
  echo "Usage:
    $0 [options]
Options:
  -k|--key-file <file-path>       Private key file to sign. Created one if not provided.
  -c|--csr-file <file-path>       CSR holding the signing request use.
  -n|--name <csr-name>            Name of the CSR object to be created.
                                  Defaults to "sgx-test-csr"
  -s|--namespace <namespace-name> Namespace of the CSR object to be created.
                                  Uses "default" namespace not provided.
  --signer                        Name of the signer. Default "intel.com/sgx"
  -h|--help                       Display this help and exit

" 2>&2
}

key_file=""
csr_file=""
csr_name="sgx-test-csr"
csr_ns="default"
signer="intel.com/sgx"

while [ $# -gt 0 ]; do

case "$1" in
  -k|--key-file)
  key_file=$2; shift; shift
  ;;

  -c|--csr-file)
  csr_file=$2; shift; shift
  ;;

  -n|--name)
  csr_name=$2; shift; shift
  ;;

  -s|--namespace)
  csr_ns=$2; shift; shift
  ;;

  --signer)
  signer=$2; shift; shift
  ;;

 -h|--help)
  Usage ; exit 0 ;;

  *) echo "Unknown option: $1" 2>&2 ; Usage
  exit 1 ;;
esac

done

if [ "$csr_file" = "" ]; then
  if [ "$key_file" = "" ]; then
    key_file=/tmp/sgx.key
    generate_key "$key_file"
  fi
  csr_file="/tmp/sgx.csr"
  generate_csr "$key_file" "$csr_file"
fi

create_k8s_csr "$csr_file" "$csr_name" "$csr_ns" "$signer" && echo "Done"