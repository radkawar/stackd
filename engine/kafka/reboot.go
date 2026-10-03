package kafka

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	msk "stackd/internal/services/kafka"
)

// Reboot restarts only the selected broker. Configuration and credential changes
// belong to Ensure; this operation does not reconcile unrelated cluster intent.
func (d *Docker) Reboot(ctx context.Context, spec msk.Specification, brokerID int32) (endpoint msk.Endpoint, result error) {
	if err := msk.ValidateSpecification(spec); err != nil {
		return endpoint, err
	}
	if brokerID < 1 || brokerID > spec.Brokers {
		return endpoint, errors.New("MSK broker ID is outside the owned cluster")
	}
	properties, err := msk.ParseProperties(spec.ServerProperties)
	if err != nil {
		return endpoint, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err = d.lock(ctx); err != nil {
		return endpoint, err
	}
	defer d.unlock()
	if err = d.ensureVolume(ctx, spec, "config", false); err != nil {
		return endpoint, err
	}
	helper, err := d.createContainer(ctx, spec, "configuration", nil)
	if err != nil {
		return endpoint, err
	}
	defer func() { result = errors.Join(result, d.detachHelper(helper.ID)) }()
	m, err := d.readMaterial(ctx, helper.ID)
	if err != nil {
		return endpoint, err
	}
	if m == nil || len(m.Nodes) != int(spec.Brokers) || m.Configuration != configurationID(spec, properties) {
		return endpoint, errors.New("MSK native configuration is not applied")
	}
	role := "broker-" + strconv.Itoa(int(brokerID))
	state, err := d.inspect(ctx, resourceName(spec, role))
	if err != nil {
		return endpoint, err
	}
	if err = d.checkContainer(state, spec, role, m); err != nil {
		return endpoint, err
	}
	if state.State.Running {
		err = d.client.JSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(state.ID)+"/stop?t=30", nil, nil)
		if err != nil && !dockerStatus(err, http.StatusNotModified) {
			return endpoint, err
		}
	}
	state, err = d.inspect(ctx, state.ID)
	if err != nil {
		return endpoint, err
	}
	if err = d.start(ctx, state); err != nil {
		return endpoint, d.failure(ctx, state.ID, err)
	}
	if err = d.ready(ctx, spec, m, properties); err != nil {
		return endpoint, err
	}
	return d.endpoint(spec, m), nil
}
