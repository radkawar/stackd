package eks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	native "stackd/compute/eks"
	"stackd/internal/awscatalog"
)

// ErrNotServiceAccountIssuer identifies foreign issuers that another discovery
// source may resolve. Missing or malformed EKS issuers never return this error.
var ErrNotServiceAccountIssuer = errors.New("not an EKS service account issuer")

// ServiceAccountIssuerCacheLifetime is the max-age observed on both native AWS
// discovery and JWKS responses in testdata/aws/eks/irsa_native.json.
const ServiceAccountIssuerCacheLifetime = 7 * 24 * time.Hour

// ServiceAccountIssuer identifies the cluster incarnation, not its mutable name
// or the account in which an IAM OIDC provider is registered.
func (c Cluster) ServiceAccountIssuer() string {
	return "https://oidc.eks." + c.Key.Region + "." + issuerDNSSuffix(c.Key.Partition) + "/id/" + strings.ToUpper(strings.ReplaceAll(c.ID, "-", ""))
}

func issuerDNSSuffix(partition string) string {
	switch partition {
	case "aws", "aws-us-gov":
		return "amazonaws.com"
	case "aws-cn":
		return "amazonaws.com.cn"
	case "aws-eusc":
		return "amazonaws.eu"
	case "aws-iso":
		return "c2s.ic.gov"
	case "aws-iso-b":
		return "sc2s.sgov.gov"
	case "aws-iso-e":
		return "cloud.adc-e.uk"
	case "aws-iso-f":
		return "csp.hci.ic.gov"
	default:
		return ""
	}
}

func serviceAccountIssuerHost(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	endpoint, ok := strings.CutPrefix(host, "oidc.eks.")
	if !ok {
		return false
	}
	region, suffix, ok := strings.Cut(endpoint, ".")
	return ok && region != "" && suffix == issuerDNSSuffix(awscatalog.RegionPartition(region))
}

func (s *Service) serviceAccountIssuerCluster(ctx context.Context, issuerURL string) (Cluster, error) {
	issuer, err := url.Parse(issuerURL)
	if err != nil {
		return Cluster{}, err
	}
	if !serviceAccountIssuerHost(issuer.Host) {
		return Cluster{}, ErrNotServiceAccountIssuer
	}
	id, ok := strings.CutPrefix(issuer.Path, "/id/")
	if issuer.Scheme != "https" || issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || issuer.RawPath != "" || issuer.Port() != "" || !ok || len(id) != 32 || strings.Trim(id, "0123456789ABCDEF") != "" {
		return Cluster{}, ErrNotFound
	}
	clusterID, err := uuid.Parse(id)
	if err != nil {
		return Cluster{}, ErrNotFound
	}
	nativeID := clusterID.String()
	var found Cluster
	err = s.repository.View(ctx, func(tx Reader) error {
		clusters, err := tx.AllClusters()
		if err != nil {
			return err
		}
		for _, c := range clusters {
			if c.ID == nativeID && c.Endpoint != "" && c.Status != "DELETING" && c.ServiceAccountIssuer() == issuerURL {
				found = c
				return nil
			}
		}
		return ErrNotFound
	})
	return found, err
}

// ServiceAccountIssuerDocuments reads the live native API server's discovery
// documents. Public discovery deliberately has no caller-account restriction.
func (s *Service) ServiceAccountIssuerDocuments(ctx context.Context, issuerURL string) (configuration, jwks []byte, err error) {
	c, err := s.serviceAccountIssuerCluster(ctx, issuerURL)
	if err != nil {
		return nil, nil, err
	}
	runtime, ok := s.runtime.(native.ServiceAccountIssuerRuntime)
	if !ok {
		return nil, nil, errors.New("native service account issuer is unavailable")
	}
	configuration, err = runtime.ServiceAccountIssuerDocument(ctx, c.ID, "/.well-known/openid-configuration")
	if err != nil {
		return nil, nil, err
	}
	jwks, err = runtime.ServiceAccountIssuerDocument(ctx, c.ID, "/openid/v1/jwks")
	if err != nil {
		return nil, nil, err
	}
	return configuration, jwks, nil
}

// ServeOIDCIssuer handles only AWS-shaped EKS issuer hosts. The native control
// plane supplies both the discovery metadata and its actual public signing keys.
func (s *Service) ServeOIDCIssuer(w http.ResponseWriter, r *http.Request) bool {
	if !serviceAccountIssuerHost(r.Host) {
		return false
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusForbidden)
		return true
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	prefix, document, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/id/"), "/")
	var nativePath string
	switch document {
	case ".well-known/openid-configuration":
		nativePath = "/.well-known/openid-configuration"
	case "keys":
		nativePath = "/openid/v1/jwks"
	}
	if !strings.HasPrefix(r.URL.Path, "/id/") || !ok || nativePath == "" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.NotFound(w, r)
		return true
	}
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	c, err := s.serviceAccountIssuerCluster(r.Context(), "https://"+host+"/id/"+prefix)
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return true
	}
	if err != nil {
		http.Error(w, "EKS issuer unavailable", http.StatusServiceUnavailable)
		return true
	}
	runtime, ok := s.runtime.(native.ServiceAccountIssuerRuntime)
	if !ok {
		http.Error(w, "EKS issuer unavailable", http.StatusServiceUnavailable)
		return true
	}
	data, err := runtime.ServiceAccountIssuerDocument(r.Context(), c.ID, nativePath)
	if err != nil {
		http.Error(w, "EKS issuer unavailable", http.StatusServiceUnavailable)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "max-age="+strconv.FormatInt(int64(ServiceAccountIssuerCacheLifetime/time.Second), 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return true
}
