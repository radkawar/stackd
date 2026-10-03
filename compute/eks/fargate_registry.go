package eks

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// RegistryAuthorization is private native execution material, never an EKS API field.
type RegistryAuthorization struct{ ServerAddress, Endpoint, Username, Password string }

func (k *K3d) configureFargateAgentFiles(ctx context.Context, container string, auth []RegistryAuthorization, flannelPort int) error {
	if len(auth) == 0 && flannelPort == 0 {
		return nil
	}
	mirrors := map[string]any{}
	configs := map[string]any{}
	for _, a := range auth {
		mirrors[a.ServerAddress] = map[string]any{"endpoint": []string{a.Endpoint}}
		configs[a.ServerAddress] = map[string]any{"auth": map[string]string{"username": a.Username, "password": a.Password}}
	}
	data, err := json.Marshal(map[string]any{"mirrors": mirrors, "configs": configs})
	if err != nil {
		return err
	}
	// JSON is valid YAML. Only the stopped exact-owned agent receives this private
	// file; no Kubernetes Secret, service-account mount or workload environment does.
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, dir := range []string{"etc/", "etc/rancher/", "etc/rancher/k3s/"} {
		if err = tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
			return err
		}
	}
	if len(auth) > 0 {
		if err = tw.WriteHeader(&tar.Header{Name: "etc/rancher/k3s/registries.yaml", Mode: 0600, Size: int64(len(data))}); err != nil {
			return err
		}
		if _, err = tw.Write(data); err != nil {
			return err
		}
	}
	if flannelPort != 0 {
		network, err := json.Marshal(map[string]any{"Network": "10.42.0.0/16", "EnableIPv4": true, "EnableIPv6": false, "Backend": map[string]any{"Type": "vxlan", "Port": flannelPort, "VNI": flannelPort}})
		if err != nil {
			return err
		}
		if err = tw.WriteHeader(&tar.Header{Name: "etc/rancher/k3s/stackd-flannel.json", Mode: 0600, Size: int64(len(network))}); err != nil {
			return err
		}
		if _, err = tw.Write(network); err != nil {
			return err
		}
	}
	if err = tw.Close(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "docker", "container", "cp", "-", container+":/")
	cmd.Env = k.commandEnvironment()
	cmd.Stdin = &archive
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("eks: installing private Fargate registry credentials: %w", err)
	}
	return nil
}
