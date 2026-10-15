package kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"stackd/compute/docker"
	msk "stackd/internal/services/kafka"
)

func (d *Docker) Ensure(ctx context.Context, spec msk.Specification) (endpoint msk.Endpoint, result error) {
	var empty msk.Endpoint
	if err := msk.ValidateSpecification(spec); err != nil {
		return empty, err
	}
	if len(spec.Networks) > 0 && !d.client.SupportsAPIVersion(1, 48) {
		return empty, errors.New("managed native Kafka requires Docker Engine API1.48 or newer for private administration gateway priority")
	}
	properties, err := msk.ParseProperties(spec.ServerProperties)
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err = d.lock(ctx); err != nil {
		return empty, err
	}
	defer d.unlock()
	// A retained container cannot acquire replacement identity or empty volumes.
	hasBroker := false
	for n := int32(1); n <= spec.Brokers; n++ {
		s, e := d.inspect(ctx, resourceName(spec, "broker-"+strconv.Itoa(int(n))))
		if e == nil {
			hasBroker = true
			if e = d.checkContainer(s, spec, "broker-"+strconv.Itoa(int(n)), nil); e != nil {
				return empty, e
			}
		} else if !dockerStatus(e, http.StatusNotFound) {
			return empty, e
		}
	}
	if err = d.ensureVolume(ctx, spec, "config", !hasBroker); err != nil {
		return empty, err
	}
	helper, err := d.createContainer(ctx, spec, "configuration", nil)
	if err != nil {
		return empty, err
	}
	defer func() { result = errors.Join(result, d.detachHelper(helper.ID)) }()
	m, err := d.readMaterial(ctx, helper.ID)
	if err != nil {
		return empty, err
	}
	fresh := m == nil
	var held []net.Listener
	defer func() {
		for _, listener := range held {
			if listener != nil {
				listener.Close()
			}
		}
	}()
	if fresh {
		if hasBroker {
			return empty, errors.New("MSK retained broker lost native identity material")
		}
		m, err = newMaterial(spec, d.endpointHost)
		if err != nil {
			return empty, err
		}
		held, err = d.reserveBrokerPorts(ctx, spec.Brokers, m)
		if err != nil {
			return empty, err
		}
	}
	if len(m.Nodes) != int(spec.Brokers) || m.ClusterID == "" || m.AdminPassword == "" {
		return empty, errors.New("MSK retained native material conflicts with broker count or identity")
	}
	if m.Networked != (len(spec.Networks) > 0) {
		return empty, errors.New("MSK retained native network mode conflicts with cluster ownership")
	}
	if err := m.validatePorts(); err != nil {
		return empty, err
	}
	if _, err = d.network(ctx, spec, true); err != nil {
		return empty, err
	}
	for n := 1; n <= int(spec.Brokers); n++ {
		if err = d.ensureVolume(ctx, spec, "data-"+strconv.Itoa(n), fresh); err != nil {
			return empty, err
		}
	}
	configID := configurationID(spec, properties)
	configChanged := m.Configuration != configID
	if configChanged {
		if err = d.stopBrokers(ctx, spec, m); err != nil {
			return empty, err
		}
	}
	if fresh || configChanged {
		if err = d.writeConfiguration(ctx, helper.ID, spec, m, properties); err != nil {
			return empty, err
		}
	}
	for node := range m.Nodes {
		role := "broker-" + strconv.Itoa(node+1)
		state, e := d.inspect(ctx, resourceName(spec, role))
		if dockerStatus(e, http.StatusNotFound) {
			if e = d.initializeData(ctx, spec, node+1); e != nil {
				return empty, e
			}
			state, e = d.createContainer(ctx, spec, role, m)
		}
		if e != nil {
			return empty, e
		}
		if e = d.checkContainer(state, spec, role, m); e != nil {
			return empty, e
		}
		if fresh {
			// Keep every other broker's sockets held until its own handoff.
			for _, listener := range held[node*2 : node*2+2] {
				if listener != nil {
					if err := listener.Close(); err != nil {
						return empty, err
					}
				}
			}
		}
		if e = d.start(ctx, state); e != nil {
			return empty, d.failure(ctx, state.ID, e)
		}
		if e = d.configureBrokerNetwork(ctx, spec, node, state); e != nil {
			return empty, e
		}
	}
	if err = d.ready(ctx, spec, m, properties); err != nil {
		return empty, err
	}
	if err = d.protectAdministration(ctx, m); err != nil {
		return empty, err
	}
	hashes := userHashes(spec)
	usersChanged := !usersApplied(m, hashes)
	persist := func() error { return d.writeConfiguration(ctx, helper.ID, spec, m, properties) }
	if usersChanged {
		err = confirmUserIntent(m, hashes, persist,
			func() error { return d.reconcileUsers(ctx, spec, m) },
			func() error {
				// Native SCRAM updates do not revoke authenticated sockets.
				// A retained restart closes them before confirmation is committed.
				if e := d.stopBrokers(ctx, spec, m); e != nil {
					return e
				}
				for node := range m.Nodes {
					state, e := d.inspect(ctx, resourceName(spec, "broker-"+strconv.Itoa(node+1)))
					if e != nil {
						return e
					}
					if e = d.start(ctx, state); e != nil {
						return e
					}
					if e = d.configureBrokerNetwork(ctx, spec, node, state); e != nil {
						return e
					}
				}
				if e := d.ready(ctx, spec, m, properties); e != nil {
					return e
				}
				m.Configuration = configID
				return nil
			})
		if err != nil {
			return empty, err
		}
	}
	// Configuration and credential confirmation are separate durable effects.
	// Credential confirmation has already committed its native proof above.
	if !usersChanged && (fresh || configChanged) {
		m.Configuration = configID
		if err = d.writeConfiguration(ctx, helper.ID, spec, m, properties); err != nil {
			return empty, err
		}
	}
	return d.endpoint(spec, m), nil
}

// persist and the two native phases are explicit to keep the interruption
// boundaries testable. Neither phase can run before durable uncertainty, and
// only native effect plus retained restart/readiness may confirm these hashes.
func confirmUserIntent(m *material, hashes map[string]string, persist, alter, restartAndProve func() error) (result error) {
	m.UsersConfirmed = false
	defer func() {
		if result != nil {
			m.UsersConfirmed = false
		}
	}()
	if err := persist(); err != nil {
		return err
	}
	if err := alter(); err != nil {
		return err
	}
	if err := restartAndProve(); err != nil {
		return err
	}
	m.UserHashes, m.UsersConfirmed = hashes, true
	return persist()
}

func (d *Docker) stopBrokers(ctx context.Context, spec msk.Specification, m *material) error {
	for node := range m.Nodes {
		role := "broker-" + strconv.Itoa(node+1)
		s, err := d.inspect(ctx, resourceName(spec, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err = d.checkContainer(s, spec, role, m); err != nil {
			return err
		}
		if s.State.Running {
			err = d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(s.ID)+"/stop?t=30", nil, nil)
			if err != nil && !dockerStatus(err, http.StatusNotModified) {
				return err
			}
		}
	}
	return nil
}

func (d *Docker) statusOnce(ctx context.Context, spec msk.Specification) (endpoint msk.Endpoint, result error) {
	var empty msk.Endpoint
	if err := msk.ValidateSpecification(spec); err != nil {
		return empty, err
	}
	properties, err := msk.ParseProperties(spec.ServerProperties)
	if err != nil {
		return empty, err
	}
	gateStarted := time.Now()
	if err = d.lock(ctx); err != nil {
		return empty, fmt.Errorf("native Kafka status gate_wait=%s: %w", time.Since(gateStarted), err)
	}
	defer d.unlock()
	gateElapsed, physicalStarted := time.Since(gateStarted), time.Now()
	quarantineNeeded := len(spec.Networks) > 0
	defer func() {
		if result != nil && quarantineNeeded {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			result = errors.Join(result, d.quarantineLocked(cleanup, spec))
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	defer func() {
		if result != nil {
			result = fmt.Errorf("native Kafka status gate_wait=%s physical_elapsed=%s: %w", gateElapsed, time.Since(physicalStarted), result)
		}
	}()
	if err = d.ensureVolume(ctx, spec, "config", false); err != nil {
		return empty, err
	}
	first, err := d.inspect(ctx, resourceName(spec, "broker-1"))
	if err != nil {
		return empty, err
	}
	if err = d.checkContainer(first, spec, "broker-1", nil); err != nil {
		return empty, err
	}
	// The exact broker mounts this retained config volume read-only. A status
	// read needs no transient configuration container or cleanup mutation.
	m, err := d.readMaterial(ctx, first.ID)
	if err != nil {
		return empty, err
	}
	if m == nil || len(m.Nodes) != int(spec.Brokers) || m.Configuration != configurationID(spec, properties) || !usersApplied(m, userHashes(spec)) {
		return empty, errors.New("MSK native configuration or SCRAM credentials are not applied")
	}
	for node := range m.Nodes {
		role := "broker-" + strconv.Itoa(node+1)
		state := first
		if node != 0 {
			state, err = d.inspect(ctx, resourceName(spec, role))
			if err != nil {
				return empty, err
			}
		}
		if err = d.checkContainer(state, spec, role, m); err != nil {
			return empty, err
		}
		if !state.State.Running {
			return empty, errors.New("MSK broker is stopped")
		}
		if err = d.configureBrokerNetwork(ctx, spec, node, state); err != nil {
			// configureBrokerNetwork has already quarantined its failed proof.
			quarantineNeeded = false
			return empty, err
		}
	}
	client, transport, err := d.adminClient(m)
	if err != nil {
		return empty, err
	}
	defer transport.CloseIdleConnections()
	if err = d.probe(ctx, client, m, properties); err != nil {
		return empty, err
	}
	return d.endpoint(spec, m), nil
}

func (d *Docker) detachHelper(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.client.RemoveContainer(ctx, id)
}

// Delete preflights every exact resource before removing any, including resources
// left by interrupted creation. It never lists or prunes by generic service tags.
func (d *Docker) Delete(ctx context.Context, spec msk.Specification) error {
	if spec.Incarnation == "" || spec.ARN == "" || spec.Partition == "" || spec.AccountID == "" || spec.Region == "" || spec.Brokers < 1 || spec.Brokers > 3 {
		return errors.New("MSK immutable ownership and broker count are required for deletion")
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	roles := []string{"configuration"}
	volumeRoles := []string{"config"}
	for n := 1; n <= int(spec.Brokers); n++ {
		text := strconv.Itoa(n)
		roles = append(roles, "broker-"+text, "init-"+text)
		volumeRoles = append(volumeRoles, "data-"+text)
	}
	containers, err := d.retainedNetworkHelpers(ctx, spec)
	if err != nil {
		return err
	}
	for _, role := range roles {
		s, err := d.inspect(ctx, resourceName(spec, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err = d.checkContainer(s, spec, role, nil); err != nil {
			return err
		}
		containers = append(containers, s)
	}
	var volumes []volumeState
	for _, role := range volumeRoles {
		v, err := d.inspectVolume(ctx, resourceName(spec, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err = d.checkVolume(v, spec, role); err != nil {
			return err
		}
		volumes = append(volumes, v)
	}
	network, err := d.network(ctx, spec, false)
	if err != nil && !dockerStatus(err, http.StatusNotFound) {
		return err
	}
	for _, s := range containers {
		if err = d.client.RemoveContainer(ctx, s.ID); err != nil {
			return err
		}
		if _, err = d.inspect(ctx, s.ID); !dockerStatus(err, http.StatusNotFound) {
			return fmt.Errorf("MSK container removal was not observed: %w", err)
		}
	}
	for _, v := range volumes {
		if err = d.client.JSON(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(v.Name), nil, nil); err != nil && !dockerStatus(err, http.StatusNotFound) {
			return err
		}
		if _, err = d.inspectVolume(ctx, v.Name); !dockerStatus(err, http.StatusNotFound) {
			return fmt.Errorf("MSK volume removal was not observed: %w", err)
		}
	}
	if network.ID != "" {
		if err = d.client.JSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(network.ID), nil, nil); err != nil && !dockerStatus(err, http.StatusNotFound) {
			return err
		}
		if _, err = d.network(ctx, spec, false); !dockerStatus(err, http.StatusNotFound) {
			return fmt.Errorf("MSK network removal was not observed: %w", err)
		}
	}
	if err = d.removeBrokerNetworks(ctx, spec); err != nil {
		return err
	}
	return nil
}

// Randomly named helpers can survive an interrupted Docker create or removal.
// Discover only this immutable owner, then preflight all results before Delete
// removes any resources. A mismatched response is never treated as ownership.
func (d *Docker) retainedNetworkHelpers(ctx context.Context, spec msk.Specification) ([]containerState, error) {
	labels := d.labels(spec, "network-helper")
	filter := make([]string, 0, len(labels))
	for key, value := range labels {
		filter = append(filter, key+"="+value)
	}
	encoded, err := json.Marshal(map[string][]string{"label": filter})
	if err != nil {
		return nil, err
	}
	var listed []struct {
		ID string `json:"Id"`
	}
	if err = d.client.JSON(ctx, http.MethodGet, "/containers/json?all=true&filters="+url.QueryEscape(string(encoded)), nil, &listed); err != nil {
		return nil, fmt.Errorf("discover retained native Kafka network helpers: %w", err)
	}
	if len(listed) == 0 {
		return nil, nil
	}
	var image struct {
		ID string `json:"Id"`
	}
	if err = d.client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(docker.ToolkitImage)+"/json", nil, &image); err != nil {
		return nil, err
	}
	if image.ID == "" {
		return nil, errors.New("native Kafka helper image has no immutable identity")
	}
	helpers := make([]containerState, 0, len(listed))
	for _, candidate := range listed {
		if candidate.ID == "" {
			return nil, errors.New("native Kafka helper has no container identity")
		}
		state, err := d.inspect(ctx, candidate.ID)
		if err != nil {
			return nil, err
		}
		if err = d.checkLabels(state.Config.Labels, spec, "network-helper"); err != nil {
			return nil, err
		}
		if state.ID != candidate.ID || state.Image != image.ID || state.Config.Image != docker.ToolkitImage ||
			state.HostConfig.Privileged || len(state.HostConfig.Binds) != 0 || len(state.HostConfig.Mounts) != 0 {
			return nil, errors.New("native Kafka helper has conflicting purpose or native image")
		}
		helpers = append(helpers, state)
	}
	return helpers, nil
}

func (d *Docker) failure(ctx context.Context, id string, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var logs bytes.Buffer
	response, err := d.client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs?stdout=true&stderr=true&tail=30", nil, "")
	if err == nil {
		err = docker.CopyStream(&logs, &logs, io.LimitReader(response.Body, 24<<10))
		response.Body.Close()
	}
	// Kafka never receives association passwords in configuration or arguments.
	return fmt.Errorf("MSK native broker %s failed: %w; logs=%q; log_error=%v", id, cause, logs.String(), err)
}
