package eks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
)

// workerArguments assigns a separate VXLAN UDP port and VNI to every retained
// cluster. Publishing a global 8472 would silently connect unrelated clusters.
// The configuration is shared with actual EC2 agents through WorkerBootstrap.
func (k *K3d) workerArguments(state diskState, dir string) ([]string, error) {
	token := sha256.Sum256([]byte(state.Token + "/managed-workers"))
	agentToken := hex.EncodeToString(token[:])
	args := []string{"--k3s-arg", "--agent-token=" + agentToken + "@server:0", "--k3s-arg", "--token=" + agentToken + "@agent:0"}
	if state.WorkerAdvertiseHost == "" {
		return args, nil
	}
	config := map[string]any{"Network": "10.42.0.0/16", "EnableIPv4": true, "EnableIPv6": false, "Backend": map[string]any{"Type": "vxlan", "Port": state.NativePort, "VNI": state.NativePort}}
	raw, e := json.Marshal(config)
	if e != nil {
		return nil, e
	}
	if e = writePrivate(dir, "stackd-flannel.json", raw); e != nil {
		return nil, e
	}
	// k3d defaults port mappings to its proxy even for an explicit agent filter.
	// This cluster has no load balancer; bind VXLAN directly on its owned worker.
	return append(args, "--volume", filepath.Join(dir, "stackd-flannel.json")+":/etc/rancher/k3s/stackd-flannel.json:ro@agent:0", "--port", net.JoinHostPort(state.WorkerAdvertiseHost, fmt.Sprint(state.NativePort))+":"+fmt.Sprint(state.NativePort)+"/udp@agent:0:direct", "--k3s-arg", "--flannel-conf=/etc/rancher/k3s/stackd-flannel.json@agent:0", "--k3s-arg", "--flannel-external-ip@server:0", "--k3s-arg", "--node-external-ip="+state.WorkerAdvertiseHost+"@agent:0"), nil
}
func (k *K3d) validateWorkerTransport(state diskState, container dockerContainer) error {
	if state.WorkerAdvertiseHost == "" {
		return nil
	}
	bindings := container.HostConfig.PortBindings[fmt.Sprint(state.NativePort)+"/udp"]
	if len(bindings) != 1 || bindings[0].HostIP != state.WorkerAdvertiseHost || bindings[0].HostPort != fmt.Sprint(state.NativePort) {
		return fmt.Errorf("eks: worker overlay endpoint differs from retained ownership")
	}
	mounted := false
	for _, m := range container.Mounts {
		if m.Destination == "/etc/rancher/k3s/stackd-flannel.json" {
			mounted = true
		}
	}
	if !mounted {
		return fmt.Errorf("eks: native worker overlay configuration mount is absent")
	}
	return nil
}
