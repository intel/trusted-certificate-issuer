# Installing with Helm 

This document covers how to install Trusted Certificate Service (TCS) issuer by using Helm charts.

## Prerequisites

> NOTE: the charts are not yet hosted anywhere so you need to point the helm to the `charts` directory.

Generate the Helm charts by using the following command.

```sh
$ make helm
```

## Installing the Chart

Use the following command to install TCS (to namespace `tcs-issuer` which will be created).

> NOTE: This will also install the CRDs.

```sh
$ helm install tcs-issuer -n tcs-issuer --create-namespace ./charts
```

Use the following command to verify the TCS installation status.

```sh
$ helm ls -n tcs-issuer
```

## Uninstalling the Chart

In case you want to uninstall TCS, use the following command:

> NOTE: the below command does not uninstall the CRDs. 

```sh
$ helm delete tcs-issuer -n tcs-issuer
```

## Configuration

The following table lists the configurable parameters of the TCS issuer chart and their default values. You can change the default values either via `helm --set <parameter=value>` or editing the `values.yaml` and passing the file to helm via `helm install -f values.yaml ...` option.

| Parameter | Description | Default 
| --- | --- | --- |
| `image.hub`| Image repository | intel |
| `image.name`| Image name | trusted-certificate-issuer |
| `image.tag`| Image tag | latest |
| `image.pullPolicy`| Image pull policy | Always |
| `controllerExtraArgs`| List of extra arguments passed to the controller  | Empty |

