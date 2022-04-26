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

package controllers_test

import (
	"context"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	csrv1 "k8s.io/api/certificates/v1"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var scheme *runtime.Scheme

const (
	testIssuerNS = "test-issuer"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}

	var err error

	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	scheme = runtime.NewScheme()
	err = csrv1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred(), "failed to add Certificate api types to scheme")
	err = corev1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred(), "failed to add core types to scheme")
	err = tcsapi.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred(), "failed to add TCS types to scheme")

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: testIssuerNS,
	}}
	err = k8sClient.Create(context.TODO(), nsObj)
	Expect(err).ShouldNot(HaveOccurred(), "create issuer namespace")
}, 60)

var _ = AfterSuite(func() {
	if k8sClient != nil {
		nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: testIssuerNS,
		}}
		k8sClient.Delete(context.TODO(), nsObj)
	}

	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
