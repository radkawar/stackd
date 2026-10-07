package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/services/cloudformation"
	"strconv"
	"strings"
)

const cfnMQAssociationOwner = cfnComputeTagPrefix + "edge-mq-configuration-owner"
const cfnMQAssociationPrevious = cfnComputeTagPrefix + "edge-mq-configuration-previous"

func cfnEngineEdgeOwner(r cloudformation.ResourceRequest) string {
	return cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
}

// The MQ API applies a configuration through UpdateBroker and RebootBroker.
// Capture the previously effective native association in broker-owned tags so
// rollback/deletion can restore it, including after a controller restart.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-amazonmq-configurationassociation.html
type cfnMQConfigurationAssociation struct{ commands StepFunctionsCommands }

func (h cfnMQConfigurationAssociation) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Broker", "Configuration"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Broker", "Configuration"); err != nil {
		return err
	}
	configuration, ok := cfnComputeObject(p["Configuration"])
	if !ok {
		return fmt.Errorf("configuration must be an object")
	}
	if err := cfnComputeProperties(configuration, "Id", "Revision"); err != nil {
		return err
	}
	return cfnComputeRequired(configuration, "Id", "Revision")
}
func (h cfnMQConfigurationAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Broker"), h.Validate(b)
}
func (h cfnMQConfigurationAssociation) id(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnComputeString(r.Properties, "Broker")
}
func (h cfnMQConfigurationAssociation) get(ctx context.Context, r cloudformation.ResourceRequest) (*api.DescribeBrokerOutput, error) {
	return cfnMQBrokerGet(ctx, h.commands, h.id(r))
}
func (h cfnMQConfigurationAssociation) owned(r cloudformation.ResourceRequest, v *api.DescribeBrokerOutput) error {
	if r.CloudControl {
		return nil
	}
	if string(v.Tags[cfnMQAssociationOwner]) != cfnEngineEdgeOwner(r) {
		return fmt.Errorf("broker configuration association is not owned by this stack incarnation")
	}
	return nil
}
func (h cfnMQConfigurationAssociation) apply(ctx context.Context, r cloudformation.ResourceRequest, configuration map[string]any) error {
	if err := cfnComputeRun(ctx, h.commands, "mq", "UpdateBroker", map[string]any{"BrokerId": h.id(r), "configuration": cfnEngineLower(configuration)}); err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "mq", "RebootBroker", map[string]any{"BrokerId": h.id(r)})
}
func (h cfnMQConfigurationAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(v.BrokerId)
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID}
	configuration, _ := cfnComputeObject(r.Properties["Configuration"])
	if v.Configurations != nil && v.Configurations.Pending != nil {
		pending := v.Configurations.Pending
		if cfnComputeValue(pending.Id) != cfnComputeString(configuration, "Id") || pending.Revision == nil || fmt.Sprint(*pending.Revision) != fmt.Sprint(configuration["Revision"]) {
			return cloudformation.ResourceResult{}, fmt.Errorf("broker has an unrelated pending configuration")
		}
	}
	existing := string(v.Tags[cfnMQAssociationOwner])
	if existing != "" && existing != cfnEngineEdgeOwner(r) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("broker already has an owned configuration association"))
	}
	if existing == "" {
		if v.Configurations == nil || v.Configurations.Current == nil || v.Configurations.Current.Revision == nil {
			return cloudformation.ResourceResult{}, fmt.Errorf("broker has no effective configuration to restore")
		}
		previous := cfnComputeValue(v.Configurations.Current.Id) + "/" + fmt.Sprint(*v.Configurations.Current.Revision)
		if err = cfnComputeRun(ctx, h.commands, "mq", "CreateTags", map[string]any{"ResourceArn": cfnComputeValue(v.BrokerArn), "tags": map[string]string{cfnMQAssociationOwner: cfnEngineEdgeOwner(r), cfnMQAssociationPrevious: previous}}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if v.Configurations != nil && v.Configurations.Pending != nil {
		return result, nil
	}
	if v.Configurations == nil {
		return result, fmt.Errorf("broker has no effective configuration")
	}
	current := v.Configurations.Current
	if current == nil || cfnComputeValue(current.Id) != cfnComputeString(configuration, "Id") || current.Revision == nil || fmt.Sprint(*current.Revision) != fmt.Sprint(configuration["Revision"]) {
		if err = h.apply(ctx, r, configuration); err != nil {
			return result, err
		}
	}
	return h.Result(ctx, r)
}
func (h cfnMQConfigurationAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cloudformation.ResourceResult{PhysicalID: h.id(r), Ref: h.id(r)}
	if err := h.Validate(r.Properties); err != nil {
		return result, err
	}
	v, err := h.get(ctx, r)
	if err != nil {
		return result, err
	}
	if err = h.owned(r, v); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Configuration") {
		configuration, _ := cfnComputeObject(r.Properties["Configuration"])
		if err = h.apply(ctx, r, configuration); err != nil {
			return result, err
		}
	}
	return h.Result(ctx, r)
}
func (h cfnMQConfigurationAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.get(ctx, r)
	if cfnEngineMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(v.Tags[cfnMQAssociationOwner]) == "" {
		if r.CloudControl {
			return fmt.Errorf("MQ cannot detach an existing broker configuration without an admitted prior association; update it to another real configuration")
		}
		return nil
	}
	if err = h.owned(r, v); err != nil {
		return err
	}
	previous := strings.SplitN(string(v.Tags[cfnMQAssociationPrevious]), "/", 2)
	if len(previous) != 2 {
		return fmt.Errorf("owned broker association has no recovery configuration")
	}
	revision, err := strconv.Atoi(previous[1])
	if err != nil {
		return err
	}
	if cfnComputeValue(v.BrokerState) != "RUNNING" {
		return nil
	}
	if v.Configurations == nil {
		return fmt.Errorf("owned broker has no effective configuration")
	}
	if v.Configurations.Pending != nil {
		pending := v.Configurations.Pending
		if cfnComputeValue(pending.Id) == previous[0] && pending.Revision != nil && int(*pending.Revision) == revision {
			return cfnComputeRun(ctx, h.commands, "mq", "RebootBroker", map[string]any{"BrokerId": h.id(r)})
		}
		desired, _ := cfnComputeObject(r.Properties["Configuration"])
		if cfnComputeValue(pending.Id) != cfnComputeString(desired, "Id") {
			return fmt.Errorf("broker has an unrelated pending configuration")
		}
	}
	current := v.Configurations.Current
	if current == nil || cfnComputeValue(current.Id) != previous[0] || current.Revision == nil || int(*current.Revision) != revision {
		if err = h.apply(ctx, r, map[string]any{"Id": previous[0], "Revision": revision}); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnMQConfigurationAssociation) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r)
	if err != nil {
		return false, err
	}
	stable, err := cfnEngineStable(cfnComputeValue(v.BrokerState), "RUNNING")
	if !stable || err != nil {
		return stable, err
	}
	if err = h.owned(r, v); err != nil {
		return false, err
	}
	if v.Configurations == nil {
		return false, fmt.Errorf("broker has no configuration")
	}
	configuration, _ := cfnComputeObject(r.Properties["Configuration"])
	if pending := v.Configurations.Pending; pending != nil {
		if cfnComputeValue(pending.Id) != cfnComputeString(configuration, "Id") || pending.Revision == nil || fmt.Sprint(*pending.Revision) != fmt.Sprint(configuration["Revision"]) {
			return false, fmt.Errorf("broker has an unrelated pending configuration")
		}
		return false, cfnComputeRun(ctx, h.commands, "mq", "RebootBroker", map[string]any{"BrokerId": h.id(r)})
	}
	current := v.Configurations.Current
	if current == nil || cfnComputeValue(current.Id) != cfnComputeString(configuration, "Id") || current.Revision == nil || fmt.Sprint(*current.Revision) != fmt.Sprint(configuration["Revision"]) {
		return false, h.apply(ctx, r, configuration)
	}
	return true, nil
}
func (h cfnMQConfigurationAssociation) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r)
	if cfnEngineMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if string(v.Tags[cfnMQAssociationOwner]) == "" {
		return true, nil
	}
	if err = h.owned(r, v); err != nil {
		return false, err
	}
	if cfnComputeValue(v.BrokerState) != "RUNNING" {
		return false, nil
	}
	if v.Configurations == nil || v.Configurations.Current == nil {
		return false, fmt.Errorf("owned broker recovery association is missing")
	}
	if v.Configurations.Pending != nil {
		return false, h.Delete(ctx, r)
	}
	previous := strings.SplitN(string(v.Tags[cfnMQAssociationPrevious]), "/", 2)
	if len(previous) != 2 {
		return false, fmt.Errorf("owned broker recovery association is missing")
	}
	current := v.Configurations.Current
	if cfnComputeValue(current.Id) != previous[0] || current.Revision == nil || fmt.Sprint(*current.Revision) != previous[1] {
		return false, h.Delete(ctx, r)
	}
	err = cfnComputeRun(ctx, h.commands, "mq", "DeleteTags", map[string]any{"ResourceArn": cfnComputeValue(v.BrokerArn), "TagKeys": []string{cfnMQAssociationOwner, cfnMQAssociationPrevious}})
	return err == nil, err
}
func (h cfnMQConfigurationAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r)
	if err != nil {
		return nil, err
	}
	if v.Configurations == nil || v.Configurations.Current == nil {
		return nil, fmt.Errorf("broker has no configuration")
	}
	return cloudformation.Properties{"Id": cfnComputeValue(v.BrokerId), "Broker": cfnComputeValue(v.BrokerId), "Configuration": map[string]any{"Id": cfnComputeValue(v.Configurations.Current.Id), "Revision": v.Configurations.Current.Revision}}, nil
}
func (h cfnMQConfigurationAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	ids, err := cfnMQBrokerIDs(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	result := []cloudformation.ResourceDescription{}
	for _, id := range ids {
		r.PhysicalID = id
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return result, nil
}
func (h cfnMQConfigurationAssociation) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEngineResult(h.id(r), p)
}
