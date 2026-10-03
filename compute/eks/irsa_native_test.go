package eks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Called by the opt-in real-k3d lifecycle test after creating a pre-IRSA server.
// It proves migration signs with the EKS issuer without invalidating old native
// credentials, and returns actual public documents for the reopen assertion.
func exerciseRetainedNativeIssuer(t *testing.T, ctx context.Context, runtime *K3d, id string, handler http.Handler) ([]byte, []byte) {
	t.Helper()
	cluster := runtime.clusters[id]
	const name = "irsa-retained"
	if err := cluster.podIdentityRequest(ctx, http.MethodPost, "/api/v1/namespaces/default/serviceaccounts", map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": name}}, nil); err != nil {
		t.Fatal(err)
	}
	token := func() string {
		t.Helper()
		var response struct{ Status struct{ Token string } }
		if err := cluster.podIdentityRequest(ctx, http.MethodPost, "/api/v1/namespaces/default/serviceaccounts/"+name+"/token", map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": map[string]any{"audiences": []string{PodIdentityAudience}, "expirationSeconds": 600}}, &response); err != nil {
			t.Fatal(err)
		}
		return response.Status.Token
	}
	claims := func(token string) map[string]any {
		t.Helper()
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatal("native TokenRequest did not return a JWT")
		}
		body, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(body, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	oldToken := token()
	if got := claims(oldToken)["iss"]; got != "https://kubernetes.default.svc.cluster.local" {
		t.Fatalf("unexpected pre-migration issuer: %v", got)
	}
	const issuer = "https://oidc.eks.us-east-1.amazonaws.com/id/1234567890ABCDEF1234567890ABCDEF"
	if _, err := runtime.Ensure(ctx, Specification{ID: id, ServiceAccountIssuer: issuer, Region: "us-east-1"}, handler); err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{oldToken, token()} {
		var review struct {
			Status struct {
				Authenticated bool
				Audiences     []string
				User          struct{ Username string }
			}
		}
		if err := cluster.podIdentityRequest(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": map[string]any{"token": credential, "audiences": []string{PodIdentityAudience}}}, &review); err != nil {
			t.Fatal(err)
		}
		if !review.Status.Authenticated || !slices.Contains(review.Status.Audiences, PodIdentityAudience) || review.Status.User.Username != "system:serviceaccount:default:"+name {
			t.Fatalf("native issuer migration invalidated a Kubernetes token: %+v", review.Status)
		}
	}
	if got := claims(token())["iss"]; got != issuer {
		t.Fatalf("new Kubernetes token issuer = %v, want %s", got, issuer)
	}
	configuration, err := runtime.ServiceAccountIssuerDocument(ctx, id, "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Issuer  string
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(configuration, &document); err != nil {
		t.Fatal(err)
	}
	if document.Issuer != issuer || document.JWKSURI != issuer+"/keys" {
		t.Fatalf("native discovery did not publish the EKS issuer: %+v", document)
	}
	jwks, err := runtime.ServiceAccountIssuerDocument(ctx, id, "/openid/v1/jwks")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Ensure(ctx, Specification{ID: id, ServiceAccountIssuer: issuer + "changed"}, handler); err == nil {
		t.Fatal("attached native cluster accepted a replacement issuer")
	}
	t.Log("real retained k3s signed EKS-issuer tokens, retained old TokenReview acceptance and served native discovery/JWKS")
	return configuration, jwks
}

func assertRetainedNativeIssuer(t *testing.T, ctx context.Context, runtime *K3d, id string, configuration, jwks []byte) {
	t.Helper()
	for path, before := range map[string][]byte{"/.well-known/openid-configuration": configuration, "/openid/v1/jwks": jwks} {
		after, err := runtime.ServiceAccountIssuerDocument(ctx, id, path)
		if err != nil {
			t.Fatal(err)
		}
		var oldDocument, newDocument any
		if err := json.Unmarshal(before, &oldDocument); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(after, &newDocument); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(oldDocument, newDocument) {
			t.Fatalf("native issuer or verification keys changed on reopen: %s", path)
		}
	}
}
