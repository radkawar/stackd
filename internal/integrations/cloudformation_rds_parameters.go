package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormation chooses each engine parameter's default apply method, not an
// invented customer ApplyMethod property. The existing parameter owner validates
// names and publishes changes to the real attached database runtime.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbparametergroup.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbclusterparametergroup.html
type cfnRDSParameterGroup struct{ commands StepFunctionsCommands }
type cfnRDSClusterParameterGroup struct{ commands StepFunctionsCommands }

// This helper is confined to RDS's two concrete parameter-group DTO contracts;
// it neither implements ResourceHandler nor provides an alternate resource store.
type cfnRDSParameterControl struct {
	commands StepFunctionsCommands
	cluster  bool
}
type cfnRDSParameterDescription struct{ name, arn, family, description string }

func (h cfnRDSParameterControl) property() string {
	if h.cluster {
		return "DBClusterParameterGroupName"
	}
	return "DBParameterGroupName"
}
func (h cfnRDSParameterControl) action(verb string) string {
	if h.cluster {
		return verb + "DBClusterParameterGroup"
	}
	return verb + "DBParameterGroup"
}
func (h cfnRDSParameterControl) kind() string {
	if h.cluster {
		return "cluster-pg"
	}
	return "pg"
}
func cfnRDSParameterEngine(family string) string {
	switch family {
	case "postgres17":
		return "postgres"
	case "mysql8.4":
		return "mysql"
	case "aurora-postgresql17":
		return "aurora-postgresql"
	case "aurora-mysql8.4":
		return "aurora-mysql"
	}
	return ""
}
func cfnRDSParameterValues(raw any) (map[string]string, error) {
	values := map[string]string{}
	if raw == nil {
		return values, nil
	}
	object, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("property Parameters must be a mapping of parameter names to scalar values")
	}
	for key, raw := range object {
		if key == "" {
			return nil, fmt.Errorf("parameter names must be nonempty")
		}
		switch v := raw.(type) {
		case string:
			values[key] = v
		case bool:
			values[key] = strconv.FormatBool(v)
		case json.Number:
			values[key] = string(v)
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("parameter %s must be finite", key)
			}
			values[key] = strconv.FormatFloat(v, 'f', -1, 64)
		case int:
			values[key] = strconv.Itoa(v)
		case int64:
			values[key] = strconv.FormatInt(v, 10)
		default:
			return nil, fmt.Errorf("parameter %s must be a scalar value", key)
		}
	}
	return values, nil
}
func (h cfnRDSParameterControl) validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, h.property(), "Description", "Family", "Parameters", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Description", "Family"); err != nil {
		return err
	}
	if h.cluster {
		if err := cfnComputeRequired(p, "Parameters"); err != nil {
			return err
		}
	}
	if err := cfnComputeStrings(p, h.property(), "Description", "Family"); err != nil {
		return err
	}
	parameters, err := cfnRDSParameterValues(p["Parameters"])
	if err != nil {
		return err
	}
	eng := cfnRDSParameterEngine(cfnComputeString(p, "Family"))
	if eng == "" {
		return fmt.Errorf("property Family is not supported by the pinned native engine")
	}
	if err := engine.ValidateParameters(eng, parameters); err != nil {
		return fmt.Errorf("property Parameters are not supported by the native engine: %w", err)
	}
	_, err = cfnComputeTags(p)
	return err
}
func (h cfnRDSParameterControl) get(ctx context.Context, name string) (cfnRDSParameterDescription, error) {
	if h.cluster {
		out, err := cfnComputeCall[api.DBClusterParameterGroupsMessage](ctx, h.commands, "rds", "DescribeDBClusterParameterGroups", map[string]any{h.property(): name})
		if err != nil {
			return cfnRDSParameterDescription{}, err
		}
		if len(out.DBClusterParameterGroups) != 1 {
			return cfnRDSParameterDescription{}, fmt.Errorf("RDS returned no cluster parameter group")
		}
		v := out.DBClusterParameterGroups[0]
		return cfnRDSParameterDescription{cfnComputeValue(v.DBClusterParameterGroupName), cfnComputeValue(v.DBClusterParameterGroupArn), cfnComputeValue(v.DBParameterGroupFamily), cfnComputeValue(v.Description)}, nil
	}
	out, err := cfnComputeCall[api.DBParameterGroupsMessage](ctx, h.commands, "rds", "DescribeDBParameterGroups", map[string]any{h.property(): name})
	if err != nil {
		return cfnRDSParameterDescription{}, err
	}
	if len(out.DBParameterGroups) != 1 {
		return cfnRDSParameterDescription{}, fmt.Errorf("RDS returned no parameter group")
	}
	v := out.DBParameterGroups[0]
	return cfnRDSParameterDescription{cfnComputeValue(v.DBParameterGroupName), cfnComputeValue(v.DBParameterGroupArn), cfnComputeValue(v.DBParameterGroupFamily), cfnComputeValue(v.Description)}, nil
}
func (h cfnRDSParameterControl) parameters(ctx context.Context, name string) (map[string]string, error) {
	parameters := map[string]string{}
	input := map[string]any{h.property(): name, "Source": "user"}
	for {
		var values api.ParametersList
		var marker string
		if h.cluster {
			out, err := cfnComputeCall[api.DBClusterParameterGroupDetails](ctx, h.commands, "rds", "DescribeDBClusterParameters", input)
			if err != nil {
				return nil, err
			}
			values, marker = out.Parameters, cfnComputeValue(out.Marker)
		} else {
			out, err := cfnComputeCall[api.DBParameterGroupDetails](ctx, h.commands, "rds", "DescribeDBParameters", input)
			if err != nil {
				return nil, err
			}
			values, marker = out.Parameters, cfnComputeValue(out.Marker)
		}
		for _, p := range values {
			parameters[cfnComputeValue(p.ParameterName)] = cfnComputeValue(p.ParameterValue)
		}
		if marker == "" {
			return parameters, nil
		}
		input["Marker"] = marker
	}
}
func (h cfnRDSParameterControl) result(v cfnRDSParameterDescription) cloudformation.ResourceResult {
	a := map[string]any{h.property(): v.name}
	if !h.cluster {
		a["DBParameterGroupArn"] = v.arn
	}
	return cloudformation.ResourceResult{PhysicalID: v.name, Ref: v.name, Attributes: a}
}
func (h cfnRDSParameterControl) publish(ctx context.Context, name, family string, desired map[string]string) error {
	current, err := h.parameters(ctx, name)
	if err != nil {
		return err
	}
	eng := cfnRDSParameterEngine(family)
	makeParameter := func(key string, value *string) map[string]any {
		method := "immediate"
		if engine.StaticParameter(eng, key) {
			method = "pending-reboot"
		}
		p := map[string]any{"ParameterName": key, "ApplyMethod": method}
		if value != nil {
			p["ParameterValue"] = *value
		}
		return p
	}
	var reset, modify []map[string]any
	for key := range current {
		if _, keep := desired[key]; !keep {
			reset = append(reset, makeParameter(key, nil))
		}
	}
	for key, value := range desired {
		if actual, found := current[key]; !found || actual != value {
			modify = append(modify, makeParameter(key, &value))
		}
	}
	// Deterministic 20-parameter service batches preserve already applied work on
	// retry, including resetting properties removed from the template.
	less := func(a, b map[string]any) int {
		return strings.Compare(a["ParameterName"].(string), b["ParameterName"].(string))
	}
	slices.SortFunc(reset, less)
	slices.SortFunc(modify, less)
	for _, batch := range []struct {
		action     string
		parameters []map[string]any
	}{{h.action("Reset"), reset}, {h.action("Modify"), modify}} {
		for start := 0; start < len(batch.parameters); start += 20 {
			end := min(start+20, len(batch.parameters))
			if err := cfnComputeRun(ctx, h.commands, "rds", batch.action, map[string]any{h.property(): name, "Parameters": batch.parameters[start:end]}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (h cfnRDSParameterControl) create(ctx context.Context, r cloudformation.ResourceRequest) (result cloudformation.ResourceResult, err error) {
	ctx = cfnRelationalContext(ctx, r, "rds", h.kind(), h.property(), 255, true)
	defer func() {
		if err != nil && result.PhysicalID == "" {
			result, err = cfnRDSCreateFailure(ctx, r, h, err)
		}
	}()
	if err := h.validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnRDSName(r, h.property(), 255)
	v, err := h.get(ctx, name)
	if err != nil {
		if !cfnRDSMissing(err) {
			return cloudformation.ResourceResult{}, err
		}
		input := map[string]any{h.property(): name, "DBParameterGroupFamily": r.Properties["Family"], "Description": r.Properties["Description"], "Tags": cfnComputeTagList(cfnRDSPublicTags(r))}
		if h.cluster {
			out, err := cfnComputeCall[api.CreateDBClusterParameterGroupResult](ctx, h.commands, "rds", "CreateDBClusterParameterGroup", input)
			if err != nil {
				return cloudformation.ResourceResult{}, err
			}
			if out.DBClusterParameterGroup == nil {
				return cloudformation.ResourceResult{}, fmt.Errorf("RDS create returned no cluster parameter group")
			}
			created := out.DBClusterParameterGroup
			result = h.result(cfnRDSParameterDescription{cfnComputeValue(created.DBClusterParameterGroupName), cfnComputeValue(created.DBClusterParameterGroupArn), cfnComputeValue(created.DBParameterGroupFamily), cfnComputeValue(created.Description)})
		} else {
			out, err := cfnComputeCall[api.CreateDBParameterGroupResult](ctx, h.commands, "rds", "CreateDBParameterGroup", input)
			if err != nil {
				return cloudformation.ResourceResult{}, err
			}
			if out.DBParameterGroup == nil {
				return cloudformation.ResourceResult{}, fmt.Errorf("RDS create returned no parameter group")
			}
			created := out.DBParameterGroup
			result = h.result(cfnRDSParameterDescription{cfnComputeValue(created.DBParameterGroupName), cfnComputeValue(created.DBParameterGroupArn), cfnComputeValue(created.DBParameterGroupFamily), cfnComputeValue(created.Description)})
		}
		v, err = h.get(ctx, name)
		if err != nil {
			return result, err
		}
	}
	result = h.result(v)
	desired, err := cfnRDSParameterValues(r.Properties["Parameters"])
	if err != nil {
		return result, err
	}
	return result, cfnRDSParameterPublicationError(h.publish(ctx, v.name, v.family, desired))
}
func (h cfnRDSParameterControl) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", h.kind(), h.property(), 255, true)
	v, err := h.get(ctx, cfnRDSName(r, h.property(), 255))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(v), nil
}
func (h cfnRDSParameterControl) update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", h.kind(), h.property(), 255, false)
	if err := h.validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := h.result(v)
	tags, err := cfnRDSTags(ctx, h.commands, v.arn)
	if err != nil {
		return result, err
	}
	if err := cfnRDSUpdateTags(ctx, h.commands, r, v.arn, tags); err != nil {
		return result, err
	}
	desired, err := cfnRDSParameterValues(r.Properties["Parameters"])
	if err != nil {
		return result, err
	}
	return result, cfnRDSParameterPublicationError(h.publish(ctx, v.name, v.family, desired))
}
func (h cfnRDSParameterControl) delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnRelationalContext(ctx, r, "rds", h.kind(), h.property(), 255, false)
	name := cfnRDSName(r, h.property(), 255)
	_, err := h.get(ctx, name)
	if cfnRDSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnRDSAbsent(cfnComputeRun(ctx, h.commands, "rds", h.action("Delete"), map[string]any{h.property(): name}))
}
func (h cfnRDSParameterControl) read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	values, err := h.parameters(ctx, v.name)
	if err != nil {
		return nil, err
	}
	parameters := make(map[string]any, len(values))
	for key, value := range values {
		parameters[key] = value
	}
	p := cloudformation.Properties{h.property(): v.name, "Family": v.family, "Description": v.description, "Parameters": parameters}
	if !h.cluster {
		p["DBParameterGroupArn"] = v.arn
	}
	tags, err := cfnRDSTags(ctx, h.commands, v.arn)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnRDSParameterControl) list(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		var names []string
		var marker string
		if h.cluster {
			out, err := cfnComputeCall[api.DBClusterParameterGroupsMessage](ctx, h.commands, "rds", "DescribeDBClusterParameterGroups", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.DBClusterParameterGroups {
				names = append(names, cfnComputeValue(v.DBClusterParameterGroupName))
			}
			marker = cfnComputeValue(out.Marker)
		} else {
			out, err := cfnComputeCall[api.DBParameterGroupsMessage](ctx, h.commands, "rds", "DescribeDBParameterGroups", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.DBParameterGroups {
				names = append(names, cfnComputeValue(v.DBParameterGroupName))
			}
			marker = cfnComputeValue(out.Marker)
		}
		for _, name := range names {
			r.PhysicalID = name
			p, err := h.read(ctx, r)
			if err != nil {
				if cfnRDSMissing(err) {
					continue
				}
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: name, Properties: p})
		}
		if marker == "" {
			return rows, nil
		}
		input["Marker"] = marker
	}
}

func cfnRDSParameterPublicationPending(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && (wire.Code == "InvalidDBInstanceState" || wire.Code == "InvalidDBClusterStateFault")
}
func cfnRDSParameterPublicationError(err error) error {
	if cfnRDSParameterPublicationPending(err) {
		return nil
	}
	return err
}
func (h cfnRDSParameterControl) stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", h.kind(), h.property(), 255, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	desired, err := cfnRDSParameterValues(r.Properties["Parameters"])
	if err != nil {
		return false, err
	}
	err = h.publish(ctx, v.name, v.family, desired)
	if cfnRDSParameterPublicationPending(err) {
		return false, nil
	}
	return err == nil, err
}
func (h cfnRDSParameterGroup) control() cfnRDSParameterControl {
	return cfnRDSParameterControl{h.commands, false}
}
func (h cfnRDSParameterGroup) Validate(p cloudformation.Properties) error {
	return h.control().validate(p)
}
func (h cfnRDSParameterGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DBParameterGroupName", "Description", "Family"), h.Validate(b)
}
func (h cfnRDSParameterGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.control().create(ctx, r)
}
func (h cfnRDSParameterGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.control().RecoverCreation(ctx, r)
}
func (h cfnRDSParameterGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.control().update(ctx, r)
}
func (h cfnRDSParameterGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return h.control().delete(ctx, r)
}
func (h cfnRDSParameterGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.control().read(ctx, r)
}
func (h cfnRDSParameterGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return h.control().list(ctx, r)
}
func (h cfnRDSParameterGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	return h.control().stabilize(ctx, r)
}
func (h cfnRDSClusterParameterGroup) control() cfnRDSParameterControl {
	return cfnRDSParameterControl{h.commands, true}
}
func (h cfnRDSClusterParameterGroup) Validate(p cloudformation.Properties) error {
	return h.control().validate(p)
}
func (h cfnRDSClusterParameterGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DBClusterParameterGroupName", "Description", "Family"), h.Validate(b)
}
func (h cfnRDSClusterParameterGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.control().create(ctx, r)
}
func (h cfnRDSClusterParameterGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.control().RecoverCreation(ctx, r)
}
func (h cfnRDSClusterParameterGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.control().update(ctx, r)
}
func (h cfnRDSClusterParameterGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return h.control().delete(ctx, r)
}
func (h cfnRDSClusterParameterGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.control().read(ctx, r)
}
func (h cfnRDSClusterParameterGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return h.control().list(ctx, r)
}
func (h cfnRDSClusterParameterGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	return h.control().stabilize(ctx, r)
}
