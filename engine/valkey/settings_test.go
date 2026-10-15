package valkey

import (
	"archive/tar"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"stackd/compute/docker"
)

func TestAccessStringsCannotOverrideCredentialAuthority(t *testing.T) {
	for _, access := range []string{"on ~* +@all nopass", "on ~* +@all >replacement", "on ~* +@all #" + strings.Repeat("a", 64), "on ~* +@all\nuser default on nopass +@all"} {
		if err := ValidateUsers([]User{{Name: "reader", AccessString: access, PasswordHashes: []string{strings.Repeat("b", 64)}}}); err == nil {
			t.Fatalf("credential override was admitted: %q", access)
		}
	}
	for _, users := range [][]User{{{Name: controllerUser, AccessString: "on ~* +@all", NoPassword: true}}, {{Name: "reader", AccessString: "on ~* +@read", NoPassword: true}, {Name: "reader", AccessString: "on ~* +@all", NoPassword: true}}} {
		if err := ValidateUsers(users); err == nil {
			t.Fatal("reserved/duplicate ACL authority was admitted")
		}
	}
}
func TestParametersCannotDisableDurabilityOrAuthentication(t *testing.T) {
	for _, name := range []string{"appendonly", "appendfsync", "requirepass", "aclfile", "bind", "port", "dir", "dbfilename", "protected-mode"} {
		if err := ValidateParameters(map[string]string{name: "no"}); err == nil {
			t.Fatalf("unsafe parameter %s was admitted", name)
		}
	}
}

func TestManagedDefaultOffACLAndStandaloneProtectedMode(t *testing.T) {
	hash := strings.Repeat("a", 64)
	users := []User{{Name: "default", AccessString: "off ~* -@all", NoPassword: true},
		{Name: "consumer", AccessString: "on ~* +@read", PasswordHashes: []string{hash}}}
	acl := aclFile(users, "controller-secret")
	if !strings.Contains(acl, "user default reset off ~* -@all nopass ") ||
		!strings.Contains(acl, "user consumer reset on ~* +@read #"+hash+" ") {
		t.Fatalf("managed ACL intent or authentication changed: %s", acl)
	}
	var configuration string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			_, _ = w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.41","Os":"linux"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/info") {
			_, _ = w.Write([]byte(`{"ID":"test-engine","OSType":"linux","MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`))
			return
		}
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/archive") {
			t.Errorf("unexpected native operation: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		archive := tar.NewReader(r.Body)
		for {
			header, err := archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Error(err)
				return
			}
			if header.Name == "node-0/valkey.conf" {
				body, err := io.ReadAll(archive)
				if err != nil {
					t.Error(err)
					return
				}
				configuration = string(body)
			}
		}
	}))
	t.Cleanup(server.Close)
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	driver := &Docker{client: client}
	m := manifest{ID: "standalone", Secret: "controller-secret", Shards: 1, Nodes: []nativeNode{{Port: 12345}}}
	if err := driver.initialize(t.Context(), containerState{ID: "exact-standalone"}, Specification{Users: users}, m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(configuration, "bind 127.0.0.1\nprotected-mode yes\n") {
		t.Fatalf("managed correction disabled standalone protection: %s", configuration)
	}
}
