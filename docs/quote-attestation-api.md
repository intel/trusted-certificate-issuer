# SGX Quote Attestation
<!-- Table of contents is auto generated using 
[Auto Markdown TOC](https://marketplace.visualstudio.com/items?itemName=huntertran.auto-markdown-toc) extension -->
<!-- TOC depthfrom:2 -->

- [Overview](#overview)
- [QuoteAttestation CRD](#quoteattestation-crd)
    - [QuoteAttestationSpec](#quoteattestationspec)
    - [QuoteAttestationStatus](#quoteattestationstatus)
        - [QuoteAttestationCondition](#quoteattestationcondition)
        - [QuoteAttestationSecret](#quoteattestationsecret)

<!-- /TOC -->

## Overview

This document describes about the API provided by the SGX operator for integrating external key services for securely provisioning the certificate authority private key and certificate.

## QuoteAttestation CRD

The `QuoteAttestation` is a namespace-scoped Kubernetes resource in the `sgx.intel.com` API group. The sgx-operator creates an object of this resource in the same namespace in which the operator is running.

The current API for `QuoteAttestation` resource is:

| Field | Type | Description |
|---|---|---|
| apiVersion | string | API version in the form of '_group/version_': sgx.intel.com/v1alpha1 |
| metadata | ObjectMeta | Object metadata such as name, namespace etc., |
| spec | QuoteAttestationSpec | Desired state of the object. |
| status | QuoteAttestationStatus | Current attestation status which supposed to be updated by the key-server/attestation-controller |

### QuoteAttestationSpec

The `QuoteAttestationSpec` defined the specification of quote attestation and contains below fields and all of its values are immutable.

| Field | Type | Description |
|---|---|---|
| quote | []byte|Base64 encoded SGX quote of the enclave |
| quoteVersion | string | Currently only supported value is _ECDSA Quote 3_. |
| serviceId | string| Unique identifier that represents service which is requesting the secret. |
| publicKey | []byte| Key must be used by the key server to encrypt the CA private key. |
| signerNames | []string | List of Kubernetes signer names needs provisioning. |

### QuoteAttestationStatus

A QuoteAttestation's status fields a `QuoteAttestationStatus` object, which carries the detailed state of the attestation request. It is comprised of attestation condition and the list of secrets.

| Field | Type | Description |
|---|---|---|
| condition | QuoteAttestationCondition | Current status condition of the attestation process. |
| secrets | map[string]QuoteAttestationSecret | The list of provisioned secrets for the given signerNames in the attestation request. |

#### QuoteAttestationCondition

| Field | Type | Description |
|---|---|---|
| type | ConditionType | Represents the status of the attestation process., one of `Success` or `Failure`. |
| state | string | A brief machine-friendly reason code(using TitleCase). |
| message | string | A detailed message of the failure for human consumption. |
| LastUpdatedTime | time | Timestamp when the status condition updated. |

#### QuoteAttestationSecret

| Field | Type | Description |
|---|---|---|
| secretName | string | Name of the [Kubernetes secret](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/secret-v1/) object that holds the encrypted CA privatekey and certificate. |
| secretType | string | 
