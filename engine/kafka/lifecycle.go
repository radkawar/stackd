package kafka

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
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
	if fresh {
		if hasBroker {
			return empty, errors.New("MSK retained broker lost native identity material")
		}
		m, err = newMaterial(spec, d.endpointHost)
		if err != nil {
			return empty, err
		}
	}
	if len(m.Nodes) != int(spec.Brokers) || m.ClusterID == "" || m.AdminPassword == "" {
		return empty, errors.New("MSK retained native material conflicts with broker count or identity")
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
		if e = d.start(ctx, state); e != nil {
			return empty, d.failure(ctx, state.ID, e)
		}
	}
	if err = d.ready(ctx, spec, m, properties); err != nil {
		return empty, err
	}
	if err = d.protectAdministration(ctx, m); err != nil {
		return empty, err
	}
	hashes := userHashes(spec)
	usersChanged := !maps.Equal(m.UserHashes, hashes)
	if usersChanged {
		if err = d.reconcileUsers(ctx, spec, m); err != nil {
			return empty, err
		}
		// Native SCRAM updates do not revoke already authenticated sockets. Retained
		// restart closes them before an association change is reported successful.
		if err = d.stopBrokers(ctx, spec, m); err != nil {
			return empty, err
		}
		for node := range m.Nodes {
			state, e := d.inspect(ctx, resourceName(spec, "broker-"+strconv.Itoa(node+1)))
			if e != nil {
				return empty, e
			}
			if e = d.start(ctx, state); e != nil {
				return empty, e
			}
		}
		if err = d.ready(ctx, spec, m, properties); err != nil {
			return empty, err
		}
	}
	// Commit the applied marker only after native readiness. Interrupted writes
	// retain the prior marker, so reattachment repeats the intended restart.
	if fresh || configChanged || usersChanged {
		m.Configuration = configID
		m.UserHashes = hashes
		if err = d.writeConfiguration(ctx, helper.ID, spec, m, properties); err != nil {
			return empty, err
		}
	}
	return d.endpoint(spec, m), nil
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

func (d *Docker) Status(ctx context.Context, spec msk.Specification) (endpoint msk.Endpoint, result error) {
	var empty msk.Endpoint
	if err := msk.ValidateSpecification(spec); err != nil {
		return empty, err
	}
	properties, err := msk.ParseProperties(spec.ServerProperties)
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err = d.lock(ctx); err != nil {
		return empty, err
	}
	defer d.unlock()
	if err = d.ensureVolume(ctx, spec, "config", false); err != nil {
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
	if m == nil || len(m.Nodes) != int(spec.Brokers) || m.Configuration != configurationID(spec, properties) {
		return empty, errors.New("MSK native configuration is not applied")
	}
	for node := range m.Nodes {
		role := "broker-" + strconv.Itoa(node+1)
		state, e := d.inspect(ctx, resourceName(spec, role))
		if e != nil {
			return empty, e
		}
		if e = d.checkContainer(state, spec, role, m); e != nil {
			return empty, e
		}
		if !state.State.Running {
			return empty, errors.New("MSK broker is stopped")
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
	var containers []containerState
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
	return nil
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
