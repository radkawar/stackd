package eks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PinnedImage returns the immutable image supplying the actual native k3s binary.
func PinnedImage(version string) (string, bool) {
	switch version {
	case "1.32":
		return "rancher/k3s:v1.32.8-k3s1@sha256:f9f125ef9c662a231a98c507afdd3ba9a94d5f02631f946d1d34000ef67f7263", true
	case "1.33":
		return K3sImage, true
	default:
		return "", false
	}
}
func SupportsVersion(version string) bool        { _, ok := PinnedImage(version); return ok }
func UpgradeAllowed(current, target string) bool { return current == "1.32" && target == "1.33" }
func nativeVersion(version string) string {
	if version == "1.32" {
		return "v1.32.8+k3s1"
	}
	if version == "1.33" {
		return "v1.33.5+k3s1"
	}
	return ""
}

func (c *nativeCluster) verifyVersion(ctx context.Context, version string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.nativeURL()+"/version", nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, response.Body)
		return fmt.Errorf("eks: native version returned %d", response.StatusCode)
	}
	var observed struct {
		GitVersion string `json:"gitVersion"`
	}
	if err = json.NewDecoder(response.Body).Decode(&observed); err != nil {
		return err
	}
	if observed.GitVersion != nativeVersion(version) {
		return fmt.Errorf("eks: native version %q does not match pinned target %q", observed.GitVersion, nativeVersion(version))
	}
	return nil
}

// UpgradePendingError means durable native cutover intent must remain pending.
// The service must retry it, not report a terminal old version over a new binary.
type UpgradePendingError struct{ Err error }

func (e *UpgradePendingError) Error() string {
	return "eks: native version cutover pending: " + e.Err.Error()
}
func (e *UpgradePendingError) Unwrap() error { return e.Err }

func (c *nativeCluster) waitVersion(ctx context.Context, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	for {
		err := c.verifyVersion(ctx, version)
		if err == nil {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("eks: version readiness: %w: %v", ctx.Err(), err)
		case <-timer.C:
		}
	}
}

// Upgrade only the agentless server using k3s' binary replacement procedure.
// Workers retain their running kubelets, containers and pod identities until
// their own node-group or Fargate lifecycle operation changes them.
func (k *K3d) upgradeNative(ctx context.Context, c *nativeCluster, target string) (err error) {
	defer func() {
		if err != nil && c.state.UpgradeTarget != "" {
			err = &UpgradePendingError{Err: err}
		}
	}()
	if target == "" {
		target = c.state.KubernetesVersion
	}
	if target == c.state.KubernetesVersion && c.state.UpgradeTarget == "" {
		return c.waitVersion(ctx, target)
	}
	if c.state.UpgradeTarget != "" && c.state.UpgradeTarget != target {
		return errors.New("eks: another native version cutover is pending")
	}
	if !UpgradeAllowed(c.state.KubernetesVersion, target) {
		return errors.New("eks: native upgrades require the next pinned Kubernetes minor version")
	}
	image, _ := PinnedImage(target)
	if _, err := k.ownedContainers(ctx, c.state); err != nil {
		return err
	}
	// Intent precedes binary extraction, rename and restart. Recovery repeats this
	// idempotently if the controller dies between any two external effects.
	c.state.UpgradeTarget = target
	if err := saveState(c.dir, c.state); err != nil {
		return err
	}
	name := "stackd-eks-upgrade-" + c.state.Token[:24]
	out, err := k.command(ctx, "docker", "container", "ls", "-aq", "--no-trunc", "--filter", "name=^/"+name+"$")
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(out))
	if id != "" {
		inspected, err := k.command(ctx, "docker", "container", "inspect", id)
		if err != nil {
			return err
		}
		var containers []dockerContainer
		if err := json.Unmarshal(inspected, &containers); err != nil {
			return err
		}
		if len(containers) != 1 || containers[0].Name != "/"+name || containers[0].Config.Labels[ownerLabel] != c.state.Token || containers[0].Config.Labels[idLabel] != c.state.ID || containers[0].Config.Image != image {
			return errors.New("eks: refusing unowned upgrade source")
		}
	} else {
		out, err = k.command(ctx, "docker", "create", "--name", name, "--label", ownerLabel+"="+c.state.Token, "--label", idLabel+"="+c.state.ID, "--entrypoint", "/bin/true", image)
		if err != nil {
			return err
		}
		id = strings.TrimSpace(string(out))
	}
	source := filepath.Join(c.dir, "upgrade-k3s")
	if _, err = k.command(ctx, "docker", "cp", id+":/bin/k3s", source); err != nil {
		return err
	}
	if _, err = k.command(ctx, "docker", "rm", "-v", id); err != nil {
		return err
	}
	defer os.Remove(source)
	server := "k3d-" + c.state.Name + "-server-0"
	if _, err = k.command(ctx, "docker", "cp", source, server+":/bin/k3s.stackd-next"); err != nil {
		return err
	}
	if _, err = k.command(ctx, "docker", "exec", server, "chmod", "0755", "/bin/k3s.stackd-next"); err != nil {
		return err
	}
	if _, err = k.command(ctx, "docker", "exec", server, "mv", "/bin/k3s.stackd-next", "/bin/k3s"); err != nil {
		return err
	}
	if _, err = k.command(ctx, "docker", "restart", "--time", "30", server); err != nil {
		return err
	}
	if err = c.waitReady(ctx); err != nil {
		return err
	}
	if err = c.waitVersion(ctx, target); err != nil {
		return err
	}
	c.state.KubernetesVersion, c.state.UpgradeTarget = target, ""
	return saveState(c.dir, c.state)
}

func (k *K3d) deleteUpgradeSource(ctx context.Context, state diskState) error {
	name := "stackd-eks-upgrade-" + state.Token[:24]
	out, err := k.command(ctx, "docker", "container", "ls", "-aq", "--no-trunc", "--filter", "name=^/"+name+"$")
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		return nil
	}
	out, err = k.command(ctx, "docker", "container", "inspect", id)
	if err != nil {
		return err
	}
	var containers []dockerContainer
	if err = json.Unmarshal(out, &containers); err != nil {
		return err
	}
	image, ok := PinnedImage(state.UpgradeTarget)
	if !ok || len(containers) != 1 || containers[0].Name != "/"+name || containers[0].Config.Labels[ownerLabel] != state.Token || containers[0].Config.Labels[idLabel] != state.ID || containers[0].Config.Image != image {
		return errors.New("eks: refusing unowned retained upgrade source")
	}
	_, err = k.command(ctx, "docker", "rm", "-v", id)
	return err
}
