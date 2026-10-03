package eks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	native "stackd/compute/eks"
	"stackd/internal/awsctx"
)

type issuerRuntime struct {
	native.Runtime
	err error
}

func (r issuerRuntime) ServiceAccountIssuerDocument(context.Context, string, string) ([]byte, error) {
	return []byte(`{"keys":[]}`), r.err
}

func issuerTestCluster() Cluster {
	return Cluster{Key: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "workloads"}, ID: "01234567-89ab-cdef-0123-456789abcdef", Status: "ACTIVE", Endpoint: "https://kubernetes.example.com"}
}

func TestClusterIssuerIdentityLifecycle(t *testing.T) {
	for _, row := range []struct {
		partition, region, suffix string
	}{
		{"aws", "us-east-1", "amazonaws.com"},
		{"aws-cn", "cn-north-1", "amazonaws.com.cn"},
		{"aws-us-gov", "us-gov-west-1", "amazonaws.com"},
	} {
		t.Run(row.partition, func(t *testing.T) {
			c := issuerTestCluster()
			c.Key.Partition, c.Key.Region = row.partition, row.region
			c.Status, c.Endpoint = "CREATING", ""
			if out := clusterAPI(c); out.Identity != nil {
				t.Fatalf("CREATING response exposed issuer before endpoint: %+v", out.Identity)
			}
			c.Status, c.Endpoint = "ACTIVE", "https://kubernetes.example.com"
			out := clusterAPI(c)
			want := "https://oidc.eks." + row.region + "." + row.suffix + "/id/0123456789ABCDEF0123456789ABCDEF"
			if out.Identity == nil || out.Identity.Oidc == nil || out.Identity.Oidc.Issuer == nil || string(*out.Identity.Oidc.Issuer) != want {
				t.Fatalf("ACTIVE response issuer=%+v, want %s", out.Identity, want)
			}
		})
	}
}

func TestServiceAccountIssuerScope(t *testing.T) {
	data, err := os.ReadFile("testdata/oidc_scope.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name, Host, Suffix, Method string
		Handled                    bool
		Status                     int
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	c := issuerTestCluster()
	repo := NewMemoryRepository(nil)
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(c) }); err != nil {
		t.Fatal(err)
	}
	s := &Service{repository: repo, runtime: issuerRuntime{}}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			r := httptest.NewRequest(row.Method, "https://"+row.Host+"/id/0123456789ABCDEF0123456789ABCDEF"+row.Suffix, nil)
			w := httptest.NewRecorder()
			if handled := s.ServeOIDCIssuer(w, r); handled != row.Handled {
				t.Fatalf("handled=%t, want %t", handled, row.Handled)
			}
			if row.Handled && w.Code != row.Status {
				t.Fatalf("HTTP %d, want %d: %s", w.Code, row.Status, w.Body.String())
			}
			if row.Method == http.MethodHead && w.Body.Len() != 0 {
				t.Fatalf("HEAD returned a document body: %q", w.Body.String())
			}
		})
	}
	for _, issuer := range []string{
		c.ServiceAccountIssuer() + "/", c.ServiceAccountIssuer() + "?issuer=other",
		strings.Replace(c.ServiceAccountIssuer(), "https:", "http:", 1),
		strings.Replace(c.ServiceAccountIssuer(), ".com/", ".com:443/", 1),
	} {
		if _, _, err := s.ServiceAccountIssuerDocuments(t.Context(), issuer); !errors.Is(err, ErrNotFound) {
			t.Errorf("owned malformed issuer %s must not fall back to external discovery: %v", issuer, err)
		}
	}
	if _, _, err := s.ServiceAccountIssuerDocuments(t.Context(), "https://accounts.example.com/issuer"); !errors.Is(err, ErrNotServiceAccountIssuer) {
		t.Fatalf("foreign issuer fallback=%v", err)
	}
}

func TestServiceAccountIssuerIncarnationAndAvailability(t *testing.T) {
	c := issuerTestCluster()
	repo := NewMemoryRepository(nil)
	put := func() {
		t.Helper()
		if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(c) }); err != nil {
			t.Fatal(err)
		}
	}
	put()
	s := &Service{repository: repo, runtime: issuerRuntime{}}
	issuer := c.ServiceAccountIssuer()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{AccountID: "222222222222", Partition: "aws", Region: "us-west-2"})
	if found, err := s.serviceAccountIssuerCluster(ctx, issuer); err != nil || found.ID != c.ID {
		t.Fatalf("cross-account issuer lookup: cluster=%+v error=%v", found, err)
	}
	c.Status = "DELETING"
	put()
	if _, _, err := s.ServiceAccountIssuerDocuments(ctx, issuer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting cluster remained discoverable: %v", err)
	}
	if err := repo.Update(ctx, func(tx Transaction) error { return tx.DeleteCluster(c.Key) }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ServiceAccountIssuerDocuments(ctx, issuer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted issuer remained discoverable: %v", err)
	}
	c.ID, c.Status = "fedcba98-7654-3210-fedc-ba9876543210", "ACTIVE"
	put()
	if _, _, err := s.ServiceAccountIssuerDocuments(ctx, issuer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("same-name recreation resurrected old issuer: %v", err)
	}
	if found, err := s.serviceAccountIssuerCluster(ctx, c.ServiceAccountIssuer()); err != nil || found.ID != c.ID {
		t.Fatalf("recreated cluster did not resolve its own issuer: cluster=%+v error=%v", found, err)
	}
	s.runtime = issuerRuntime{err: errors.New("native control plane unavailable")}
	request := httptest.NewRequest(http.MethodGet, c.ServiceAccountIssuer()+"/keys", nil)
	response := httptest.NewRecorder()
	if !s.ServeOIDCIssuer(response, request) || response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable native issuer fabricated usable keys: HTTP %d", response.Code)
	}
}
