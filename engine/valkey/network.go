package valkey

import (
	"bytes"
	"context"
	"crypto/rand"
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
)

const admissionGate = "/dev/shm/stackd-network-ready"

func (d *Docker) inspectNamed(ctx context.Context, name string) (containerState, error) {
	var s containerState
	err := d.client.JSON(ctx, "GET", "/containers/"+url.PathEscape(name)+"/json", nil, &s)
	return s, err
}
func (d *Docker) execute(ctx context.Context, id string, command []string) ([]byte, error) {
	var created struct {
		ID string `json:"Id"`
	}
	input := struct {
		AttachStdout, AttachStderr bool
		Cmd                        []string
	}{true, true, command}
	if err := d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(id)+"/exec", input, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("native Valkey exec has no identity")
	}
	response, err := d.client.Request(ctx, "POST", "/exec/"+url.PathEscape(created.ID)+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
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
	if err = d.client.JSON(ctx, "GET", "/exec/"+url.PathEscape(created.ID)+"/json", nil, &exit); err != nil {
		return nil, err
	}
	if exit.Running || exit.ExitCode != 0 {
		return nil, fmt.Errorf("native Valkey command failed: running=%t exit=%d stderr=%q", exit.Running, exit.ExitCode, stderr.String())
	}
	return stdout.Bytes(), nil
}

// A helper cleanup resolves its random name and fences the exact immutable
// owner/configuration even when Docker accepted a create after cancellation.
func (d *Docker) runManagedHelper(ctx context.Context, spec Specification, role string, config docker.ContainerConfig) (output []byte, result error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	config.Labels[labelPrefix+"helper-config"] = string(encoded)
	name := "stackd-valkey-helper-" + rand.Text()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		s, err := d.inspectNamed(cleanup, name)
		if dockerStatus(err, 404) {
			return
		}
		if err == nil {
			err = d.checkManagedHelper(s, spec, role, config)
		}
		if err == nil {
			err = d.client.RemoveContainer(cleanup, s.ID)
		}
		result = errors.Join(result, err)
	}()
	if err := d.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, nil); err != nil {
		return nil, err
	}
	s, err := d.inspectNamed(ctx, name)
	if err != nil {
		return nil, err
	}
	if err = d.checkManagedHelper(s, spec, role, config); err != nil {
		return nil, err
	}
	if err = d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(s.ID)+"/start", nil, nil); err != nil {
		return nil, err
	}
	var exit struct {
		StatusCode int64
		Error      *struct{ Message string }
	}
	if err = d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(s.ID)+"/wait?condition=not-running", nil, &exit); err != nil {
		return nil, err
	}
	response, err := d.client.Request(ctx, "GET", "/containers/"+url.PathEscape(s.ID)+"/logs?stdout=true&stderr=true", nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var stdout, stderr bytes.Buffer
	bounded := &io.LimitedReader{R: response.Body, N: (64 << 10) + 1}
	if err = docker.CopyStream(&stdout, &stderr, bounded); err != nil {
		return nil, err
	}
	if bounded.N == 0 {
		return nil, errors.New("native Valkey helper output exceeds bound")
	}
	if exit.StatusCode != 0 || (exit.Error != nil && exit.Error.Message != "") {
		return nil, fmt.Errorf("native Valkey helper failed: exit=%d stderr=%q", exit.StatusCode, stderr.String())
	}
	return stdout.Bytes(), nil
}
func (d *Docker) networkHelper(ctx context.Context, spec Specification, index int, mode string, command, environment []string) ([]byte, error) {
	role := "network-helper-" + strconv.Itoa(index+1)
	config := docker.ContainerConfig{Image: docker.ToolkitImage, Entrypoint: command, Env: environment, Labels: d.managedLabels(spec, role),
		HostConfig: docker.ContainerHostConfig{NetworkMode: mode, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges:true"}, Memory: 64 << 20, MemorySwap: 64 << 20, PidsLimit: 32}}
	config.User, config.WorkingDir = "0:0", "/"
	config.Labels[labelPrefix+"target"] = mode
	return d.runManagedHelper(ctx, spec, role, config)
}

// Called only while d.gate is held. The current callback, not a pre-lock policy
// snapshot, is installed before admitting this actual-IP listener.
func (d *Docker) configureNodeNetwork(ctx context.Context, spec Specification, index int, state containerState) error {
	if d.networks == nil || spec.RefreshNetwork == nil {
		return errors.New("managed Valkey networking requires current EC2 observation and bridge management")
	}
	current, err := spec.RefreshNetwork(ctx, index)
	if err != nil {
		return err
	}
	if !sameAttachment(spec.Networks[index], current) {
		return errors.New("managed Valkey attachment changed during current EC2 observation")
	}
	return d.networks.WithBridge(ctx, current.Network, func(bridge network.Bridge) error {
		s, err := d.inspectNamed(ctx, state.ID)
		if err != nil {
			return err
		}
		if err = d.checkManagedContainer(s, spec, nodeRole(index)); err != nil {
			return err
		}
		endpoint, exists := s.NetworkSettings.Networks[bridge.Name]
		if !exists || len(s.NetworkSettings.Networks) != 1 || endpoint.IPAddress != current.Network.Address.String() || endpoint.Gateway != current.Network.Gateway.String() || !strings.EqualFold(endpoint.MacAddress, current.Network.MAC) {
			return errors.New("managed Valkey endpoint differs from exact EC2 reservation")
		}
		output, err := d.networkHelper(ctx, spec, index, "container:"+state.ID, []string{"/bin/sh", "-ec", `for interface in /sys/class/net/*; do if [ "$(cat "$interface/address")" = "$MAC" ]; then cat "$interface/iflink"; exit 0; fi; done; exit 1`}, []string{"MAC=" + strings.ToLower(current.Network.MAC)})
		if err != nil {
			return err
		}
		ifindex, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil || ifindex <= 0 {
			return fmt.Errorf("invalid native Valkey veth index %q", output)
		}
		output, err = d.networkHelper(ctx, spec, index, "host", []string{"ip", "-d", "-j", "link", "show", "master", bridge.Device}, nil)
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
			return errors.New("managed Valkey has no exact owned external veth")
		}
		identity := attachment(spec, index)
		if err = d.networks.ApplyPolicy(ctx, identity.PolicyTable, current.Network, current.Network.Policy, peer, network.Options{PublicOwner: identity.PolicyOwner}, bridge); err != nil {
			return err
		}
		_, err = d.execute(ctx, state.ID, []string{"/bin/sh", "-ec", ": > " + admissionGate})
		return err
	})
}
func sameAttachment(a, b NodeNetwork) bool {
	return a.InterfaceID == b.InterfaceID && a.Network.NetworkID == b.Network.NetworkID && a.Network.Address == b.Network.Address &&
		a.Network.Gateway == b.Network.Gateway && a.Network.Pool == b.Network.Pool && strings.EqualFold(a.Network.MAC, b.Network.MAC)
}

// Quarantine deliberately needs no packet observation. It stops only the exact
// immutable owner and retains data, policy descriptors and EC2 reservations.
func (d *Docker) Quarantine(ctx context.Context, spec Specification) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	return d.quarantineManaged(ctx, spec)
}
func (d *Docker) quarantineManaged(ctx context.Context, spec Specification) error {
	if spec.ID == "" || spec.Shards < 1 || spec.Replicas < 0 || spec.Shards*(spec.Replicas+1) > 32 {
		return errors.New("managed Valkey immutable owner and topology required for quarantine")
	}
	if _, err := managedScope(spec.ClusterARN); err != nil {
		return err
	}
	owner, found, err := d.managedDescriptor(ctx, spec.ID)
	if err != nil {
		return err
	}
	if found {
		if owner.ClusterARN != spec.ClusterARN || owner.Shards != spec.Shards || owner.Replicas != spec.Replicas {
			return errors.New("managed Valkey quarantine ownership differs")
		}
		spec = owner.specification()
	}
	var result error
	for i := range int(spec.Shards * (spec.Replicas + 1)) {
		s, err := d.inspectNamed(ctx, d.name(spec.ID, nodeRole(i)))
		if dockerStatus(err, 404) {
			continue
		}
		if err == nil {
			err = d.checkManagedOwner(s.Config.Labels, spec, nodeRole(i))
		}
		if err == nil && s.Image != d.image {
			err = errors.New("managed Valkey quarantine refuses a foreign image")
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if !s.State.Running {
			continue
		}
		err = d.client.JSON(ctx, "POST", "/containers/"+url.PathEscape(s.ID)+"/stop?t=0", nil, nil)
		if err != nil && !dockerStatus(err, http.StatusNotModified) {
			result = errors.Join(result, err)
			continue
		}
		stopped, err := d.inspectNamed(ctx, s.ID)
		if dockerStatus(err, 404) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if stopped.State.Running {
			result = errors.Join(result, errors.New("managed Valkey quarantine was not observed"))
		}
	}
	return result
}
