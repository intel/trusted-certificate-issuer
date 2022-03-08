# Trusted Certificate Service deployment in Azure

This document describe the steps how to deploy Trusted Certificate Service (TCS) in Azure.

## Prerequisites
 
- Install and learn how to use the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/)
- [Azure account](https://portal.azure.com/)
- One or more Azure DCsv3 VM SKUs in your cluster

## Create Kubernetes cluster on Azure

You would need a Azure Kubernetes cluster (AKS) with at least one confidential computing (SGX) node. To learn more about Azure confidential computing click [here](https://docs.microsoft.com/en-us/azure/confidential-computing/).

> NOTE: When creating the resource group (`az group create`) ensure the location has [DCsv3](https://docs.microsoft.com/en-us/azure/virtual-machines/dcv3-series) instances.

Follow the cluster creating istructions [here](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-enclave-nodes-aks-get-started#create-an-aks-cluster-with-a-system-node-pool).

## Deploy Trusted Certificate Service

Once you have the cluster running in Azure you can deploy TCS normally for example using [Helm](./helm.md).
