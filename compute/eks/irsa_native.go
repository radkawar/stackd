package eks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"

	"gopkg.in/yaml.v3"
)

// ServiceAccountIssuerRuntime exposes only public documents from the real
// Kubernetes API server, using the runtime's authenticated native TLS client.
type ServiceAccountIssuerRuntime interface {
	ServiceAccountIssuerDocument(context.Context, string, string) ([]byte, error)
}

// ServiceAccountIssuerCertificate returns a read-only copy of the configured
// public frontend certificate PEM, not the native API server CA or private key.
func (k *K3d) ServiceAccountIssuerCertificate() []byte {
	return slices.Clone(k.config.PodIdentityCA)
}

func (k *K3d) ServiceAccountIssuerDocument(ctx context.Context, id, path string) ([]byte, error) {
	if path != "/.well-known/openid-configuration" && path != "/openid/v1/jwks" {
		return nil, errors.New("eks: unsupported service account issuer document")
	}
	k.mu.RLock()
	c, closed := k.clusters[id], k.closed
	k.mu.RUnlock()
	if closed || c == nil {
		return nil, errors.New("eks: cluster runtime is unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.nativeURL()+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, response.Body)
		return nil, fmt.Errorf("eks: native service account issuer document returned %d", response.StatusCode)
	}
	const limit = 2 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, errors.New("eks: native service account issuer document exceeds size limit")
	}
	return body, nil
}

func retainServiceAccountIssuer(state *diskState, dir, issuer string) error {
	if issuer == "" || state.ServiceAccountIssuer == issuer {
		return nil
	}
	if state.ServiceAccountIssuer != "" {
		return errors.New("eks: service account issuer differs from persisted cluster identity")
	}
	next := *state
	next.ServiceAccountIssuer = issuer
	if err := saveState(dir, next); err != nil {
		return err
	}
	state.ServiceAccountIssuer = next.ServiceAccountIssuer
	return nil
}

func serviceAccountIssuerArguments(issuer string) []string {
	// k3s' trailing '-' prepends our signing issuer to its accepted issuers.
	// Replacing the default would invalidate already-issued Kubernetes tokens.
	return []string{"service-account-issuer-=" + issuer, "service-account-jwks-uri=" + issuer + "/keys"}
}

func (k *K3d) installServiceAccountIssuer(ctx context.Context, state *diskState, dir string) error {
	if state.ServiceAccountIssuer == "" || state.NativeServiceAccountIssuer {
		return nil
	}
	if _, err := k.ownedContainers(ctx, *state); err != nil {
		return err
	}
	// The drop-in survives binary upgrades and server restarts without replacing
	// the native filesystem, signing key, endpoint or running workload agents.
	// TODO: Comeback — rotate the real signing key every seven days, retaining
	// public verification keys until all tokens signed by each key have expired.
	config, err := yaml.Marshal(map[string]any{"kube-apiserver-arg+": serviceAccountIssuerArguments(state.ServiceAccountIssuer)})
	if err != nil {
		return err
	}
	if err = writePrivate(dir, "native-irsa.yaml", config); err != nil {
		return err
	}
	server := "k3d-" + state.Name + "-server-0"
	if _, err = k.command(ctx, "docker", "exec", server, "mkdir", "-p", "/etc/rancher/k3s/config.yaml.d"); err != nil {
		return err
	}
	if _, err = k.command(ctx, "docker", "cp", filepath.Join(dir, "native-irsa.yaml"), server+":/etc/rancher/k3s/config.yaml.d/97-stackd-irsa.yaml"); err != nil {
		return err
	}
	if _, err = k.command(ctx, "docker", "restart", "--time", "30", server); err != nil {
		return err
	}
	next := *state
	next.NativeServiceAccountIssuer = true
	if err = saveState(dir, next); err != nil {
		return err
	}
	state.NativeServiceAccountIssuer = true
	return nil
}
