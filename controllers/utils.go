/*
Copyright 2021 Intel(R).

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
package controllers

import (
	"context"
	"fmt"
	"strings"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type IssuerRef struct {
	types.NamespacedName
	Kind string
}

func IssuerSpecAndStatus(issuer client.Object) (*tcsapi.TCSIssuerSpec, *tcsapi.TCSIssuerStatus, error) {
	switch t := issuer.(type) {
	case *tcsapi.TCSIssuer:
		return &t.Spec, &t.Status, nil
	case *tcsapi.TCSClusterIssuer:
		return &t.Spec, &t.Status, nil
	}
	return nil, nil, fmt.Errorf("unrecognized issuer type")
}

func SignerNameForIssuer(issuerGVK schema.GroupVersionKind, name, ns string) string {
	if issuerGVK.Kind == "TCSClusterIssuer" {
		ns = "" // Ignore namespace for cluster-scoped type
	}
	signerName := strings.ToLower(issuerGVK.GroupKind().String()) + "/"
	if ns != "" {
		return signerName + ns + "." + name
	}
	return signerName + name
}

func IssuerRefForSignerName(signerName string) *IssuerRef {
	parts := strings.SplitN(signerName, "/", 2)
	if len(parts) != 2 {
		return nil
	}

	kindGroup := strings.SplitN(parts[0], ".", 2)
	if len(kindGroup) != 2 {
		return nil
	}
	if kindGroup[1] != tcsapi.GroupName {
		return nil
	}

	issuer := &IssuerRef{}
	switch strings.ToLower(kindGroup[0]) {
	case "tcsissuer", "tcsissuers":
		issuer.Kind = "TCSIssuer"
	case "tcsclusterissuer", "tcsclusterissuers":
		issuer.Kind = "TCSClusterIssuer"
	default:
		return nil
	}

	nameParts := strings.SplitN(parts[1], ".", 2)
	if len(nameParts) == 2 {
		issuer.Namespace = nameParts[0]
		issuer.Name = nameParts[1]
	} else {
		issuer.Name = nameParts[0]
	}

	return issuer
}

func GetIssuer(ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	issuerRef *IssuerRef) (client.Object, error) {
	typeMeta := metav1.TypeMeta{
		Kind:       issuerRef.Kind,
		APIVersion: tcsapi.GroupVersion.String(),
	}
	var issuer client.Object
	switch issuerRef.Kind {
	case "TCSClusterIssuer":
		issuer = &tcsapi.TCSClusterIssuer{TypeMeta: typeMeta}
	case "TCSIssuer":
		issuer = &tcsapi.TCSIssuer{TypeMeta: typeMeta}
	default:
		return nil, fmt.Errorf("unknown issuer kind '%s'", issuerRef.Kind)
	}

	// Get the Issuer or ClusterIssuer
	if err := c.Get(ctx, issuerRef.NamespacedName, issuer); err != nil {
		return nil, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	return issuer, nil
}
