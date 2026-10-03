package sts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"stackd/clock"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuthHTTPIntrospectionAndRedaction(t *testing.T) {
	now := time.Unix(1789120000, 0)
	var mode atomic.Value
	mode.Store("valid")
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if mode.Load().(string) == "redirect" {
			http.Redirect(w, r, "https://unconfigured.example.com/steal", http.StatusFound)
			return
		}
		if mode.Load().(string) == "reject" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/amazon" {
			if r.URL.Query().Get("access_token") != "synthetic|access+token" {
				t.Error("access token encoding changed")
			}
			json.NewEncoder(w).Encode(map[string]any{"iss": "https://www.amazon.com", "user_id": "amazon-user", "aud": "client-id", "app_id": "application-id", "exp": 600})
			return
		}
		if r.URL.Query().Get("input_token") != "synthetic|access+token" || r.URL.Query().Get("access_token") != "app|secret" {
			t.Error("Facebook introspection parameters changed")
		}
		expires := now.Add(time.Hour).Unix()
		if mode.Load().(string) == "expired" {
			expires = now.Add(-time.Second).Unix()
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"is_valid": true, "type": "USER", "user_id": "facebook-user", "app_id": "facebook-app", "expires_at": expires}})
	}))
	defer server.Close()
	source, err := NewHTTPOAuthTokenSource(OAuthHTTPConfig{Client: server.Client(), AmazonTokenInfoURL: server.URL + "/amazon", FacebookDebugTokenURL: server.URL + "/facebook", FacebookAppAccessToken: "app|secret", Clock: clock.NewManual(now)})
	if err != nil {
		t.Fatal(err)
	}
	amazon, err := source.VerifyOAuthAccessToken(context.Background(), "www.amazon.com", "synthetic|access+token")
	if err != nil || amazon.Subject != "amazon-user" || amazon.Audience != "client-id" || amazon.TrustContext["www.amazon.com:app_id"][0] != "application-id" {
		t.Fatalf("Amazon=%+v %v", amazon, err)
	}
	facebook, err := source.VerifyOAuthAccessToken(context.Background(), "graph.facebook.com", "synthetic|access+token")
	if err != nil || facebook.Subject != "facebook-user" || facebook.Audience != "facebook-app" {
		t.Fatalf("Facebook=%+v %v", facebook, err)
	}
	facebook.TrustContext["graph.facebook.com:id"][0] = "mutation"
	if facebook.SessionContext["graph.facebook.com:id"][0] != "facebook-user" {
		t.Fatal("session context aliases trust input")
	}
	for _, value := range []string{"expired", "reject", "redirect"} {
		mode.Store(value)
		before := calls.Load()
		_, err := source.VerifyOAuthAccessToken(context.Background(), "graph.facebook.com", "synthetic|access+token")
		if err == nil || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s leaked or accepted token: %v", value, err)
		}
		if calls.Load() != before+1 {
			t.Fatal("unexpected introspection redirect")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = source.VerifyOAuthAccessToken(canceled, "www.amazon.com", "synthetic|access+token")
	if err == nil || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("canceled introspection=%v", err)
	}
}
