package eks

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Keep worker names within the 63-byte DNS-label limit and Linux's 64-byte
// hostname limit. Retain the whole pod slot; full labels enforce ownership.
func fargateAgentName(state diskState, slot string) string {
	return "k3d-fargate-" + state.Token[:16] + "-" + slot
}

// Each admitted Pod receives a separate real k3s agent/container network namespace.
// Kubernetes, not this adapter, starts and reports the workload containers.
func (k *K3d) ownedFargateContainer(state diskState, c dockerContainer) bool {
	labels := c.Config.Labels
	slot := labels[fargateSlotLabel]
	if len(slot) != 32 {
		return false
	}
	if _, err := hex.DecodeString(slot); err != nil {
		return false
	}
	image, ok := PinnedImage(labels["stackd.eks.kubernetes-version"])
	return ok && c.Config.Image == image && labels[fargateIDLabel] != "" && labels[ownerLabel] == state.Token && labels[idLabel] == state.ID && labels["k3d.cluster"] == state.Name && c.Name == "/"+fargateAgentName(state, slot)
}
func (k *K3d) ReconcileFargate(ctx context.Context, s FargateSpecification) error {
	// TODO: Comeback implement OS-patch eviction and scheduled termination.
	// Ordinary profile deletion is not an AWS patch-maintenance notification.
	k.op.Lock()
	defer k.op.Unlock()
	c, err := k.componentCluster(s.ClusterID)
	if err != nil {
		return err
	}
	containers, err := k.ownedContainers(ctx, c.state)
	if err != nil {
		return err
	}
	if err = c.ensureFargateWebhook(ctx); err != nil {
		return err
	}
	var pods struct {
		Items []fargatePod `json:"items"`
	}
	if _, err = c.componentRequest(ctx, "GET", "/api/v1/pods?labelSelector="+url.QueryEscape(fargateIDLabel+"="+s.ID), "", nil, &pods); err != nil {
		return err
	}
	slots := map[string]fargatePod{}
	for _, pod := range pods.Items {
		slot := pod.Metadata.Labels[fargateSlotLabel]
		if len(slot) != 32 {
			return errors.New("eks: invalid Fargate workload slot")
		}
		if _, err = hex.DecodeString(slot); err != nil {
			return err
		}
		if _, duplicate := slots[slot]; duplicate {
			return errors.New("eks: multiple pods claim the same isolated Fargate worker")
		}
		slots[slot] = pod
	}
	if s.Delete {
		for _, pod := range pods.Items {
			path := "/api/v1/namespaces/" + url.PathEscape(pod.Metadata.Namespace) + "/pods/" + url.PathEscape(pod.Metadata.Name)
			code, e := c.componentRequest(ctx, "DELETE", path, "application/json", map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": pod.Metadata.UID}}, nil)
			if e != nil && code != 404 {
				return e
			}
		}
		for _, container := range containers {
			if container.Config.Labels[fargateIDLabel] == s.ID {
				if err = k.removeFargateAgent(ctx, c, container, true); err != nil {
					return err
				}
			}
		}
		for _, pod := range pods.Items {
			if err = c.waitComponentDeleted(ctx, "/api/v1/namespaces/"+url.PathEscape(pod.Metadata.Namespace)+"/pods/"+url.PathEscape(pod.Metadata.Name)); err != nil {
				return err
			}
		}
		remaining, err := k.currentFargateProfiles(ctx, c)
		if err != nil {
			return err
		}
		last := true
		for _, profile := range remaining {
			if profile.ID != s.ID {
				last = false
				break
			}
		}
		if last {
			name := "stackd-fargate-" + c.state.Token[:16]
			path := "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/" + name
			var hook struct {
				Metadata componentMetadata `json:"metadata"`
			}
			code, err := c.componentRequest(ctx, "GET", path, "", nil, &hook)
			if code != 404 {
				if err != nil {
					return err
				}
				if hook.Metadata.Labels[ownerLabel] != c.state.Token[:32] {
					return errors.New("eks: Fargate webhook ownership changed")
				}
				_, err = c.componentRequest(ctx, "DELETE", path, "application/json", map[string]any{"preconditions": map[string]string{"uid": hook.Metadata.UID}}, nil)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	existing := map[string]dockerContainer{}
	for _, container := range containers {
		if container.Config.Labels[fargateIDLabel] != s.ID {
			continue
		}
		slot := container.Config.Labels[fargateSlotLabel]
		if _, ok := slots[slot]; !ok {
			if err = k.removeFargateAgent(ctx, c, container, false); err != nil {
				return err
			}
		} else {
			existing[slot] = container
		}
	}
	if s.AdmissionDenied {
		return nil
	}
	for slot, pod := range slots {
		container, ok := existing[slot]
		if ok && container.State.Running {
			continue
		}
		var auth []RegistryAuthorization
		if s.RegistryAuthorization != nil {
			images := make([]string, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
			for _, v := range pod.Spec.Containers {
				images = append(images, v.Image)
			}
			for _, v := range pod.Spec.InitContainers {
				images = append(images, v.Image)
			}
			auth, err = s.RegistryAuthorization(ctx, images)
			if err != nil {
				return err
			}
		}
		if ok {
			port := 0
			if c.state.WorkerAdvertiseHost != "" {
				port = c.state.NativePort
			}
			if err = k.configureFargateAgentFiles(ctx, container.ID, auth, port); err != nil {
				return err
			}
			if _, err = k.command(ctx, "docker", "container", "start", container.ID); err != nil {
				return err
			}
			continue
		}
		if err = k.createFargateAgent(ctx, c, s, slot, auth); err != nil {
			return err
		}
	}
	return nil
}
func (k *K3d) createFargateAgent(ctx context.Context, c *nativeCluster, s FargateSpecification, slot string, auth []RegistryAuthorization) error {
	server := "k3d-" + c.state.Name + "-server-0"
	token, err := k.command(ctx, "docker", "exec", server, "cat", "/var/lib/rancher/k3s/server/agent-token")
	if err != nil {
		return err
	}
	joinToken := strings.TrimSpace(string(token))
	if joinToken == "" {
		return errors.New("eks: native node join token is empty")
	}
	version := c.state.KubernetesVersion
	image, ok := PinnedImage(version)
	if !ok {
		return errors.New("eks: unsupported Fargate worker version")
	}
	name := fargateAgentName(c.state, slot)
	args := []string{"container", "create", "--name", name, "--hostname", name, "--network", c.state.Name, "--privileged", "--restart", "unless-stopped", "--tmpfs", "/run", "--tmpfs", "/var/run", "--volume", "/var/lib/rancher/k3s", "--label", ownerLabel + "=" + c.state.Token, "--label", idLabel + "=" + c.state.ID, "--label", "k3d.cluster=" + c.state.Name, "--label", fargateIDLabel + "=" + s.ID, "--label", fargateSlotLabel + "=" + slot, "--label", "stackd.eks.kubernetes-version=" + version, "--env", "K3S_TOKEN=" + joinToken, image, "agent", "--server", "https://" + server + ":6443", "--node-name", name, "--node-label", fargateSlotLabel + "=" + slot, "--node-label", fargateIDLabel + "=" + s.ID, "--node-label", fargateProfileLabel + "=" + s.Name, "--node-label", "eks.amazonaws.com/compute-type=fargate", "--node-taint", "eks.amazonaws.com/compute-type=fargate:NoSchedule", "--kubelet-arg", "max-pods=1"}
	port := 0
	if c.state.WorkerAdvertiseHost != "" {
		port = c.state.NativePort
		args = append(args, "--flannel-conf", "/etc/rancher/k3s/stackd-flannel.json")
	}
	if _, err = k.command(ctx, "docker", args...); err != nil {
		return err
	}
	if err = k.configureFargateAgentFiles(ctx, name, auth, port); err != nil {
		return err
	}
	_, err = k.command(ctx, "docker", "container", "start", name)
	return err
}
func (k *K3d) removeFargateAgent(ctx context.Context, c *nativeCluster, container dockerContainer, drain bool) error {
	if !k.ownedFargateContainer(c.state, container) {
		return errors.New("eks: refusing unowned Fargate agent deletion")
	}
	name := strings.TrimPrefix(container.Name, "/")
	var node struct {
		Metadata componentMetadata `json:"metadata"`
	}
	code, err := c.componentRequest(ctx, "GET", "/api/v1/nodes/"+url.PathEscape(name), "", nil, &node)
	if err != nil && code != 404 {
		return err
	}
	if code != 404 {
		if node.Metadata.Labels[fargateSlotLabel] != container.Config.Labels[fargateSlotLabel] || node.Metadata.Labels[fargateIDLabel] != container.Config.Labels[fargateIDLabel] {
			return errors.New("eks: Fargate node identity changed")
		}
		if drain {
			deadline, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			for {
				done, e := k.DrainWorker(deadline, c.state.ID, name, node.Metadata.UID, false)
				if e != nil {
					return e
				}
				if done {
					break
				}
				select {
				case <-deadline.Done():
					return fmt.Errorf("eks: Fargate drain: %w", deadline.Err())
				case <-time.After(time.Second):
				}
			}
		}
	}
	if _, err = k.command(ctx, "docker", "container", "rm", "--force", "--volumes", container.ID); err != nil {
		return err
	}
	if code != 404 {
		return k.DeleteWorker(ctx, c.state.ID, name, node.Metadata.UID)
	}
	return nil
}
