package kafka

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
	"stackd/compute/network"
	msk "stackd/internal/services/kafka"
)

func brokerNetwork(spec msk.Specification, role string) (msk.BrokerNetwork, bool) {
	if !strings.HasPrefix(role, "broker-") || len(spec.Networks) == 0 {
		return msk.BrokerNetwork{}, false
	}
	id, err := strconv.Atoi(strings.TrimPrefix(role, "broker-"))
	if err != nil || id < 1 || id > len(spec.Networks) {
		return msk.BrokerNetwork{}, false
	}
	return spec.Networks[id-1], true
}

func brokerPolicyTable(spec msk.Specification, id int) string {
	return fmt.Sprintf("stackd_msk_%x", sha256.Sum256([]byte(spec.ARN+"\x00"+spec.Incarnation+"\x00"+strconv.Itoa(id))))
}
func brokerPolicyOwner(spec msk.Specification, id int) string {
	return spec.ARN + "\x00" + spec.Incarnation + "\x00" + strconv.Itoa(id)
}

func (d *Docker) execute(ctx context.Context, id string, command []string) ([]byte, error) {
	var created struct {
		ID string `json:"Id"`
	}
	input := struct {
		AttachStdout, AttachStderr bool
		Cmd                        []string
	}{true, true, command}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/exec", input, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("native Kafka exec returned no identity")
	}
	response, err := d.client.Request(ctx, http.MethodPost, "/exec/"+url.PathEscape(created.ID)+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	err = docker.CopyStream(&stdout, &stderr, io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	var exit struct {
		Running  bool
		ExitCode int
	}
	if err = d.client.JSON(ctx, http.MethodGet, "/exec/"+url.PathEscape(created.ID)+"/json", nil, &exit); err != nil {
		return nil, err
	}
	if exit.Running || exit.ExitCode != 0 {
		return nil, fmt.Errorf("native Kafka command failed: running=%t exit=%d stderr=%q", exit.Running, exit.ExitCode, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (d *Docker) networkHelper(ctx context.Context, spec msk.Specification, mode string, command, environment []string) ([]byte, error) {
	return docker.RunHelper(ctx, d.client, "msk-network", docker.ContainerConfig{
		Image: docker.ToolkitImage, Entrypoint: command, Env: environment,
		Labels:     d.labels(spec, "network-helper"),
		HostConfig: docker.ContainerHostConfig{NetworkMode: mode, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32},
	})
}

// Read and admission-marker commands run only in the same exact live broker
// incarnation on both sides of the effect. A same-ID restart is a new namespace.
func (d *Docker) executeOwnedBroker(ctx context.Context, spec msk.Specification, index int, expected containerState, command []string) ([]byte, error) {
	role := "broker-" + strconv.Itoa(index+1)
	check := func() error {
		current, err := d.inspect(ctx, expected.ID)
		if err != nil {
			return err
		}
		if err = d.checkContainer(current, spec, role, nil); err != nil {
			return err
		}
		if current.ID != expected.ID || !current.State.Running || current.State.Pid <= 0 || current.State.StartedAt == "" ||
			current.State.Pid != expected.State.Pid || current.State.StartedAt != expected.State.StartedAt {
			return errors.New("native Kafka broker process identity changed during packet observation")
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	output, err := d.execute(ctx, expected.ID, command)
	return output, errors.Join(err, check())
}

// configureBrokerNetwork installs the outside-customer veth policy before the
// gated broker opens any client listener. Interbroker TLS stays on its distinct
// owned private bridge; CLIENT binds only the EC2-reserved address.
func (d *Docker) configureBrokerNetwork(ctx context.Context, spec msk.Specification, index int, state containerState) (result error) {
	if len(spec.Networks) == 0 {
		return nil
	}
	phase, phaseStarted := "current authority", time.Now()
	var authorityElapsed time.Duration
	defer func() {
		if result != nil {
			// A failed refresh cannot leave the previous permissive policy serving.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			result = errors.Join(result, d.quarantineLocked(cleanup, spec))
		}
	}()
	defer func() {
		if result != nil {
			result = fmt.Errorf("native Kafka broker-%d packet proof phase=%s phase_elapsed=%s authority_elapsed=%s: %w", index+1, phase, time.Since(phaseStarted), authorityElapsed, result)
		}
	}()
	if d.networks == nil || len(spec.Networks) != int(spec.Brokers) {
		return errors.New("native Kafka broker networks are unavailable")
	}
	attachment := spec.Networks[index]
	if spec.RefreshNetwork == nil {
		return errors.New("native Kafka packet policy requires current EC2 observation")
	}
	current, err := spec.RefreshNetwork(ctx, index)
	authorityElapsed = time.Since(phaseStarted)
	if err != nil {
		return err
	}
	if current.InterfaceID != attachment.InterfaceID || current.Network.Address != attachment.Network.Address || current.Network.MAC != attachment.Network.MAC || current.Network.NetworkID != attachment.Network.NetworkID {
		return errors.New("native Kafka attachment identity changed during policy observation")
	}
	attachment = current
	phase, phaseStarted = "existing bridge admission/lifetime lock", time.Now()
	return d.networks.WithExistingBridge(ctx, attachment.Network, func(bridge network.Bridge) error {
		phase, phaseStarted = "existing broker endpoint", time.Now()
		current, err := d.inspect(ctx, state.ID)
		if err != nil {
			return err
		}
		endpoint, exists := current.NetworkSettings.Networks[bridge.Name]
		if !exists || endpoint.IPAddress != attachment.Network.Address.String() || endpoint.Gateway != attachment.Network.Gateway.String() || !strings.EqualFold(endpoint.MacAddress, attachment.Network.MAC) {
			return errors.New("native Kafka endpoint differs from its EC2-owned reservation")
		}
		if len(current.NetworkSettings.Networks) != 2 {
			return errors.New("native Kafka broker has an unexpected network attachment")
		}
		phase, phaseStarted = "broker namespace peer", time.Now()
		output, err := d.executeOwnedBroker(ctx, spec, index, current, []string{"/bin/bash", "-ec", `for interface in /sys/class/net/*; do if [ "$(cat "$interface/address")" = "$1" ]; then cat "$interface/iflink"; exit 0; fi; done; exit 1`, "--", strings.ToLower(attachment.Network.MAC)})
		if err != nil {
			return err
		}
		ifindex, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil || ifindex <= 0 {
			return fmt.Errorf("invalid native Kafka veth index %q", output)
		}
		phase, phaseStarted = "native host veth", time.Now()
		output, err = d.networkHelper(ctx, spec, "host", []string{"ip", "-d", "-j", "link", "show", "master", bridge.Device}, nil)
		if err != nil {
			return err
		}
		var links []struct {
			IfIndex  int    `json:"ifindex"`
			IfName   string `json:"ifname"`
			Master   string `json:"master"`
			LinkInfo struct {
				Kind string `json:"info_kind"`
			} `json:"linkinfo"`
		}
		if err = json.Unmarshal(output, &links); err != nil {
			return err
		}
		peer := ""
		for _, link := range links {
			if link.IfIndex == ifindex && link.Master == bridge.Device && link.LinkInfo.Kind == "veth" {
				peer = link.IfName
				break
			}
		}
		if peer == "" {
			return errors.New("native Kafka has no owned external veth; refusing an unfiltered client listener")
		}
		phase, phaseStarted = "native full policy installation", time.Now()
		if err = d.networks.ApplyPolicy(ctx, brokerPolicyTable(spec, index+1), attachment.Network, attachment.Network.Policy, peer, network.Options{PublicOwner: brokerPolicyOwner(spec, index+1)}, bridge); err != nil {
			return err
		}
		phase, phaseStarted = "broker admission marker", time.Now()
		_, err = d.executeOwnedBroker(ctx, spec, index, current, []string{"/bin/bash", "-ec", ": > /mnt/shared/config/stackd-network-ready"})
		if err == nil {
			phase, phaseStarted = "existing bridge final identity", time.Now()
		}
		return err
	})
}

func (d *Docker) removeBrokerNetworks(ctx context.Context, spec msk.Specification) error {
	if len(spec.Networks) == 0 {
		return nil
	}
	if d.networks == nil {
		return errors.New("native Kafka bridge manager is unavailable for deletion")
	}
	for index, attachment := range spec.Networks {
		if err := d.networks.RemovePolicy(ctx, brokerPolicyTable(spec, index+1), brokerPolicyOwner(spec, index+1)); err != nil {
			return err
		}
		if err := d.networks.Release(ctx, attachment.Network.NetworkID); err != nil {
			return err
		}
	}
	return nil
}

// Quarantine stops exact-owned broker processes, retaining their volumes and
// reservations for a later valid reconciliation. It needs no EC2 observation.
func (d *Docker) Quarantine(ctx context.Context, spec msk.Specification) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	return d.quarantineLocked(ctx, spec)
}

func (d *Docker) quarantineLocked(ctx context.Context, spec msk.Specification) error {
	if spec.Incarnation == "" || spec.ARN == "" || spec.Partition == "" || spec.AccountID == "" || spec.Region == "" || spec.Brokers < 1 || spec.Brokers > 3 {
		return errors.New("MSK immutable ownership and broker count are required for quarantine")
	}
	var result error
	for broker := 1; broker <= int(spec.Brokers); broker++ {
		role := "broker-" + strconv.Itoa(broker)
		state, err := d.inspect(ctx, resourceName(spec, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if err = d.checkLabels(state.Config.Labels, spec, role); err != nil {
			result = errors.Join(result, err)
			continue
		}
		if state.Image != d.imageID {
			result = errors.Join(result, errors.New("MSK quarantine refuses a foreign broker image"))
			continue
		}
		if !state.State.Running {
			continue
		}
		err = d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/stop?t=0", nil, nil)
		if err != nil && !dockerStatus(err, http.StatusNotModified) {
			result = errors.Join(result, err)
			continue
		}
		stopped, err := d.inspect(ctx, state.ID)
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if stopped.State.Running {
			result = errors.Join(result, errors.New("MSK broker quarantine was not observed"))
		}
	}
	return result
}
