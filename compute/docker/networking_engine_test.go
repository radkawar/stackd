package docker

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRuntimeNetworkingEngine runs a real customer-shaped container. Set
// STACKD_RUNTIME_NETWORKING_DOCKER_HOST (e.g. unix:///var/run/docker.sock) on a
// Linux daemon with ToolkitImage installed and host-gateway reachability to this
// process. curl verifies TLS through AWS_CA_BUNDLE without disabling verification.
func TestRuntimeNetworkingEngine(t *testing.T) {
	host := os.Getenv("STACKD_RUNTIME_NETWORKING_DOCKER_HOST")
	if host == "" {
		t.Skip("set STACKD_RUNTIME_NETWORKING_DOCKER_HOST to run against a real Docker Engine")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	client, err := New(ctx, Config{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	caCertificate, caKey, ca := testCertificate(t, true, nil, nil)
	leafCertificate, leafKey, _ := testCertificate(t, false, caCertificate, caKey)
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "verified") }), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafCertificate.Raw}, PrivateKey: leafKey, Leaf: leafCertificate}}}}
	go server.ServeTLS(listener, "", "")
	t.Cleanup(func() { server.Close() })
	_, port, _ := net.SplitHostPort(listener.Addr().String())

	networking := Networking{DNS: []string{"192.0.2.53"}, CAFile: writeFile(t, ca)}
	if err := networking.Validate(); err != nil {
		t.Fatal(err)
	}
	script := `set -e; cat /etc/resolv.conf; echo "bundle=$AWS_CA_BUNDLE"; grep -c 'BEGIN CERTIFICATE' "$AWS_CA_BUNDLE"; ` +
		`curl --silent --show-error --max-time 10 --cacert "$AWS_CA_BUNDLE" https://host.docker.internal:` + port + `/; echo; ` +
		`if chmod u+w "$AWS_CA_BUNDLE" 2>/dev/null && printf altered >> "$AWS_CA_BUNDLE" 2>/dev/null; then echo mutable-trust; exit 1; fi; ` +
		`if curl --silent --max-time 10 https://host.docker.internal:` + port + `/ >/dev/null 2>&1; then echo unverified-accepted; fi`
	config := ContainerConfig{Image: ToolkitImage, Entrypoint: []string{"/bin/sh", "-c", script}, Labels: map[string]string{"io.stackd.test": "runtime-networking"}, HostConfig: ContainerHostConfig{
		ReadonlyRootfs: true, Memory: 128 << 20, MemorySwap: 128 << 20, PidsLimit: 64, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
		ExtraHosts: []string{"host.docker.internal:host-gateway"}, DNS: networking.DNS, LogConfig: ContainerLogConfig{Type: "json-file"},
	}}
	var image struct{ Config struct{ Env []string } }
	if err := client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(ToolkitImage)+"/json", nil, &image); err != nil {
		t.Fatalf("toolkit image must be installed: %v", err)
	}
	trust, err := networking.PrepareTrust(&config, image.Config.Env, "")
	if err != nil || trust == nil {
		t.Fatalf("trust: %v", err)
	}
	name := "stackd-runtime-networking-test-" + strings.ToLower(rand.Text())
	var created struct {
		ID string `json:"Id"`
	}
	if err := client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := client.RemoveContainer(cleanup, created.ID); err != nil {
			t.Error(err)
		}
	})
	if missing, err := TrustMissing(ctx, client, created.ID, config.Labels, config.Env); err != nil || !missing {
		t.Fatalf("uninstalled bundle not detected: %v %v", missing, err)
	}
	if err := trust.Install(ctx, client, created.ID); err != nil {
		t.Fatal(err)
	}
	if missing, err := TrustMissing(ctx, client, created.ID, config.Labels, config.Env); err != nil || missing {
		t.Fatalf("installed bundle not detected: %v %v", missing, err)
	}
	path := "/containers/" + url.PathEscape(created.ID)
	if err := client.JSON(ctx, http.MethodPost, path+"/start", nil, nil); err != nil {
		t.Fatal(err)
	}
	var exit struct{ StatusCode int64 }
	if err := client.JSON(ctx, http.MethodPost, path+"/wait?condition=not-running", nil, &exit); err != nil {
		t.Fatal(err)
	}
	response, err := client.Request(ctx, http.MethodGet, path+"/logs?stdout=true&stderr=true", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := readHelperOutput(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	output := string(stdout)
	if exit.StatusCode != 0 || !strings.Contains(output, "nameserver 192.0.2.53") || !strings.Contains(output, "bundle=/stackd-trust/ca-bundle.pem") || !strings.Contains(output, "verified") || strings.Contains(output, "unverified-accepted") {
		t.Fatalf("exit %d stdout %q stderr %q", exit.StatusCode, stdout, stderr)
	}
	for _, line := range strings.Split(output, "\n") {
		var count int
		if _, err := fmt.Sscanf(line, "%d", &count); err == nil && count < 2 {
			t.Fatalf("image public roots were not preserved in the bundle: %q", output)
		}
	}
}
