package athena

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

// localNetwork witnesses the actual network namespace, not a socket pathname or
// daemon hostname (both can describe a forwarded/VM Engine). Only the installed
// trusted image runs here; host networking itself creates no host interface.
func localNetwork(ctx context.Context, client *docker.Client, image string) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, nil
	}
	var info struct{ SecurityOptions []string }
	if err := client.JSON(ctx, http.MethodGet, "/info", nil, &info); err != nil {
		return false, err
	}
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "rootless") || strings.Contains(option, "userns") {
			return false, nil
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return false, err
	}
	nonce := rand.Text()
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+nonce {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, nonce)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	// curl is part of the pinned Trino image (including its health check).
	// Only an ordinary negative reachability witness selects remote topology.
	// Engine, helper, cancellation and cleanup failures remain constructor errors.
	output, err := docker.RunHelper(ctx, client, "athena-network", docker.ContainerConfig{
		Image: image, User: "1000:1000", Entrypoint: []string{"/bin/sh", "-c"},
		Healthcheck: &docker.ContainerHealthConfig{Test: []string{"NONE"}},
		Cmd:         []string{"curl --silent --show-error --fail --noproxy '*' --connect-timeout 1 --max-time 2 \"$1\"; status=$?; case \"$status\" in 7|22|28) exit 0;; *) exit \"$status\";; esac", "stackd-network", "http://" + listener.Addr().String() + "/" + nonce},
		HostConfig:  docker.ContainerHostConfig{NetworkMode: "host", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, Memory: 64 << 20, MemorySwap: 64 << 20, CPUPeriod: 100000, CPUQuota: 100000, PidsLimit: 16, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}}},
	})
	if err != nil {
		return false, fmt.Errorf("witness Athena daemon network: %w", err)
	}
	return bytes.Equal(output, []byte(nonce)), nil
}

type executionNetwork struct {
	port, endpoint, nodeProperties string
	reservation                    net.Listener
}

func (d *Docker) executionNetwork() (*executionNetwork, error) {
	if !d.hostNetwork {
		return &executionNetwork{port: "8080"}, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &executionNetwork{
		port: strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), endpoint: "http://" + listener.Addr().String(), reservation: listener,
		// bind-ip controls the actual Airlift HTTP listener; internal-address
		// controls advertisement only and is not a substitute for bind-ip.
		nodeProperties: "node.bind-ip=127.0.0.1\nnode.internal-address=127.0.0.1\nnode.external-address=127.0.0.1\n",
	}, nil
}

func (n *executionNetwork) close() {
	if n.reservation != nil {
		n.reservation.Close()
		n.reservation = nil
	}
}
