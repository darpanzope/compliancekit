// compliancekit-operator entrypoint.
//
// v1.15 phase 3 — basic K8s operator. Watches ComplianceSchedule
// + ScanJob CRDs and reconciles them against a configured
// compliancekit daemon URL + the local cluster's Pod API.
//
// Flags:
//
//	--metrics-bind-address (default ":8080")
//	--health-probe-bind-address (default ":8081")
//	--leader-elect (default false)
//	--default-image (default "ghcr.io/darpanzope/compliancekit:latest")
package main

import (
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/darpanzope/compliancekit/internal/operator"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(operator.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr  string
		probeAddr    string
		leaderElect  bool
		defaultImage string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "TCP address the metrics server binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "TCP address the probe endpoints bind to.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election for HA deployments.")
	flag.StringVar(&defaultImage, "default-image", "ghcr.io/darpanzope/compliancekit:latest", "Image used for ScanJob Pods when spec.image is empty.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "compliancekit-operator.compliancekit.io",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to start manager: %v\n", err)
		os.Exit(1)
	}

	if err := (&operator.ScheduleReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to set up ScheduleReconciler: %v\n", err)
		os.Exit(1)
	}
	if err := (&operator.ScanJobReconciler{Client: mgr.GetClient(), DefaultImage: defaultImage}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "unable to set up ScanJobReconciler: %v\n", err)
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		fmt.Fprintf(os.Stderr, "unable to add healthz: %v\n", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		fmt.Fprintf(os.Stderr, "unable to add readyz: %v\n", err)
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "manager exited with error: %v\n", err)
		os.Exit(1)
	}
}
