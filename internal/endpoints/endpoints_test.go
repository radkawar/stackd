package endpoints

import (
	"strings"
	"testing"
)

func TestResourceURLRetainsExplicitOriginTransport(t *testing.T) {
	for _, row := range []struct{ origin, domain, service, region, id, want string }{
		{"https://127.0.0.1:4566", "dev.example", "lambda-url", "us-east-1", "abc", "https://abc.lambda-url.us-east-1.dev.example:4566/"},
		{"http://[::1]:8080/", "DEV.EXAMPLE", "opensearch", "eu-west-2", "incarnation", "http://incarnation.opensearch.eu-west-2.dev.example:8080/"},
		{"wss://public.example", "dev.example", "execute-api", "us-east-1", "api1", "wss://api1.execute-api.us-east-1.dev.example/"},
		{"http://localhost:4566", "dev.example", "sqs", "us-east-1", "", "http://sqs.us-east-1.dev.example:4566/"},
		{"https://localhost:4566", "", "", "", "", "https://localhost:4566/"},
	} {
		got, err := ResourceURL(row.origin, row.domain, row.service, row.region, row.id)
		if err != nil || got != row.want {
			t.Fatalf("ResourceURL(%q): %q, %v; want %q", row.origin, got, err, row.want)
		}
	}
}
func TestResourceURLRejectsImplicitOrAmbiguousConfiguration(t *testing.T) {
	for _, origin := range []string{"", "localhost:4566", "//localhost:4566", "ftp://localhost", "http://user@localhost", "http://localhost/path", "http://localhost/%2F", "http://localhost?", "http://localhost#", "http://localhost:", "http://localhost:0", "http://localhost:65536", "http://bad_host"} {
		if got, err := ResourceURL(origin, "dev.example", "sqs", "us-east-1", ""); err == nil {
			t.Fatalf("invalid origin %q accepted as %q", origin, got)
		}
	}
	for _, domain := range []string{"dev.example.", ".example", "dev..example", "127.0.0.1", "bad_name", "-bad.example", "https://dev.example", "dev.example:53", strings.Repeat("a", 64) + ".example", " dev.example"} {
		if got, err := ResourceURL("http://localhost", domain, "sqs", "us-east-1", ""); err == nil {
			t.Fatalf("invalid domain %q accepted as %q", domain, got)
		}
	}
	if _, err := ResourceURL("http://localhost", "example", "sqs", "us-east-1", "not.an.id"); err == nil {
		t.Fatal("multi-label resource ID accepted")
	}
}
func TestResourceHostClaimsOnlyConfiguredServiceNamespace(t *testing.T) {
	for _, row := range []struct {
		host, id, region string
		matched          bool
	}{
		{"ABC.lambda-url.us-east-1.dev.example:4566", "abc", "us-east-1", true},
		{"abc.lambda-url.us-east-1.dev.example.", "abc", "us-east-1", true},
		{"abc.lambda-url.eu-west-2.foreign.example", "", "", false},
		{"abc.execute-api.us-east-1.dev.example", "", "", false},
		{"abc.lambda-url.us-east-1.dev.example.evil", "", "", false},
		{"extra.abc.lambda-url.us-east-1.dev.example", "", "", true},
		{"abc.lambda-url.bad_region.dev.example", "", "", true},
	} {
		id, region, matched := ResourceHost(row.host, "dev.example", "lambda-url")
		if id != row.id || region != row.region || matched != row.matched {
			t.Fatalf("host %q: %q %q %t", row.host, id, region, matched)
		}
	}
}
