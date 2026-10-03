// Package eks runs exact-owned real Kubernetes clusters, separate from AWS control state.
package eks

import (
	"context"
	"net/http"
)

// KubernetesVersion is the API minor version selected by the pinned native image.
const KubernetesVersion = "1.33"
const K3sImage = "rancher/k3s:v1.33.5-k3s1@sha256:fd4740667b7033055c27d424d0d2d660bf66cedbdb225d68e0eab6dd48aa0fd2"
const K3dVersion = "v5.8.3"

// NodeImage identifies an imported firmware image containing the matching
// Kubernetes agent and its air-gap image archive.
type NodeImage struct {
	ImageID        string `json:"imageId"`
	ReleaseVersion string `json:"releaseVersion"`
	AmiType        string `json:"amiType"`
}

type Specification struct {
	ID                   string
	Version              string
	Logging              []string
	LogSink              LogSink
	AuditSink            AuditSink
	PodIdentityHandler   http.Handler
	FargateAuthorize     func(context.Context, string) error
	FargateProfiles      func(context.Context) ([]FargateSpecification, error)
	PodIdentityEndpoint  string
	ServiceAccountIssuer string
	Region               string
}
type Endpoint struct{ URL, CertificateAuthority string }

// Grant selects a pinned AWS access-policy role and cluster or namespace scope.
type Grant struct {
	Role       string
	Namespaces []string
}
type Identity struct {
	Username string
	Groups   []string
	Grants   []Grant
	UID      string
	Extra    map[string][]string
}

// Ensure reattaches an existing exact-owned cluster and stable TLS listener, or creates it.
// Its handler authenticates every public request before Proxy impersonates the admitted identity.
// Close closes listeners only; Delete is the only cluster removal path.
type Runtime interface {
	Ensure(context.Context, Specification, http.Handler) (Endpoint, error)
	Delete(context.Context, string) error
	Proxy(http.ResponseWriter, *http.Request, string, Identity)
	Close() error
}
