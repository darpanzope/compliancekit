package k8s

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// loadScopes reads the kubeconfig (resolved via the operator's
// override path or the standard chain) and resolves the requested
// context selection into a list of ContextScope values, one per
// context the operator wants to scan.
func loadScopes(opts Options) ([]*ContextScope, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.KubeconfigPath != "" {
		rules.ExplicitPath = opts.KubeconfigPath
	}

	raw, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if len(raw.Contexts) == 0 {
		return nil, fmt.Errorf("kubeconfig has no contexts (looked in %s)", rules.GetExplicitFile())
	}

	chosen, err := selectContexts(raw, opts.Contexts)
	if err != nil {
		return nil, err
	}

	scopes := make([]*ContextScope, 0, len(chosen))
	for _, name := range chosen {
		scope, err := buildScope(raw, name, opts)
		if err != nil {
			return nil, fmt.Errorf("context %q: %w", name, err)
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// selectContexts returns the list of context names to scan. Empty
// requested list means "just the current-context" — operators who
// want to scan multiple clusters list them explicitly.
func selectContexts(raw *clientcmdapi.Config, requested []string) ([]string, error) {
	if len(requested) == 0 {
		if raw.CurrentContext == "" {
			return nil, fmt.Errorf("kubeconfig has no current-context and providers.kubernetes.contexts is empty")
		}
		return []string{raw.CurrentContext}, nil
	}
	out := make([]string, 0, len(requested))
	for _, name := range requested {
		if _, ok := raw.Contexts[name]; !ok {
			return nil, fmt.Errorf("context %q not in kubeconfig", name)
		}
		out = append(out, name)
	}
	return out, nil
}

// buildScope assembles a single ContextScope, including the typed
// client-go clientset for that context.
func buildScope(raw *clientcmdapi.Config, name string, opts Options) (*ContextScope, error) {
	kctx, ok := raw.Contexts[name]
	if !ok {
		return nil, fmt.Errorf("not in kubeconfig")
	}
	server := ""
	if cluster, ok := raw.Clusters[kctx.Cluster]; ok {
		server = cluster.Server
	}

	cc := clientcmd.NewNonInteractiveClientConfig(*raw, name, &clientcmd.ConfigOverrides{}, nil)
	restCfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("rest config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("clientset: %w", err)
	}

	return &ContextScope{
		Name:              name,
		Server:            server,
		Namespaces:        append([]string{}, opts.Namespaces...),
		ExcludeNamespaces: append([]string{}, opts.ExcludeNamespaces...),
		Client:            cs,
		restConfig:        restCfg,
	}, nil
}
