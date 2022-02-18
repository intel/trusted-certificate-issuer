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

package main

import (
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	_ "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	tcsapi "github.com/intel/trusted-certificate-issuer/api/v1alpha1"
	"github.com/intel/trusted-certificate-issuer/controllers"
	"github.com/intel/trusted-certificate-issuer/internal/config"
	"github.com/intel/trusted-certificate-issuer/internal/sgx"
	//+kubebuilder:scaffold:imports
)

const (
	DefaultQuoteVersion   = "ECDSA Quote 3"
	instanceName          = "sgx.quote.attestation.deliver"
	quoteAttestationCtrlr = "quote-attestation-controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(tcsapi.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	cfg := config.Config{}

	flag.StringVar(&cfg.MetricsAddress, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&cfg.HealthProbeAddress, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&cfg.LeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&cfg.CertManagerIssuer, "cert-manager-issuer", true, "Run it as issuer for cert-manager.")
	flag.StringVar(&cfg.HSMTokenLabel, "token-label", "SgxOperator", "PKCS11 label to use for the operator token.")
	flag.StringVar(&cfg.HSMUserPin, "user-pin", "", "PKCS11 token user pin.")
	flag.StringVar(&cfg.HSMSoPin, "so-pin", "", "PKCS11 token so/admin pin.")
	flag.BoolVar(&cfg.CSRFullCertChain, "csr-full-cert-chain", false, "Return full certificate chain in Kubernetes CSR certificate.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog := ctrl.Log.WithName("setup")

	if err := cfg.Validate(); err != nil {
		setupLog.Error(err, "Invald operator configuration")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     cfg.MetricsAddress,
		Port:                   9443,
		HealthProbeBindAddress: cfg.HealthProbeAddress,
		LeaderElection:         cfg.LeaderElection,
		LeaderElectionID:       "bb9c3a43.sgx.intel.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	sgxctx, err := sgx.NewContext(cfg, mgr.GetClient())
	if err != nil {
		setupLog.Error(err, "SGX initialization")
		os.Exit(1)
	}
	setupLog.V(2).Info("SGX initialization SUCCESS")
	defer sgxctx.Destroy()

	if err = (&controllers.IssuerReconciler{
		Client:      mgr.GetClient(),
		Log:         ctrl.Log.WithName("controllers").WithName("TCSIssuer"),
		Kind:        "TCSIssuer",
		Scheme:      mgr.GetScheme(),
		KeyProvider: sgxctx,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TCSIssuer")
		os.Exit(1)
	}
	if err = (&controllers.IssuerReconciler{
		Client:      mgr.GetClient(),
		Log:         ctrl.Log.WithName("controllers").WithName("TCSClusterIssuer"),
		Kind:        "TCSClusterIssuer",
		Scheme:      mgr.GetScheme(),
		KeyProvider: sgxctx,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TCSClusterIssuer")
		os.Exit(1)
	}

	r := controllers.NewQuoteAttestationReconciler(mgr.GetClient(), sgxctx, nil)
	if err := r.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "QuoteAttestation")
		os.Exit(1)
	}
	if err = controllers.NewCSRReconciler(mgr.GetClient(), mgr.GetScheme(), sgxctx, cfg.CSRFullCertChain).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CSR")
		os.Exit(1)
	}

	if cfg.CertManagerIssuer {
		if err = (&controllers.CertificateRequestReconciler{
			Client:      mgr.GetClient(),
			Log:         ctrl.Log.WithName("controllers").WithName("CertificateRequest"),
			Scheme:      mgr.GetScheme(),
			KeyProvider: sgxctx,
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create controller", "controller", "CertificateRequest")
			os.Exit(1)
		}
	}

	//+kubebuilder:scaffold:builder
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
