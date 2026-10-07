package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/rds"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/docdb"
	"stackd/internal/services/rds"
)

// CloudFormationRelationalHandlers exposes only resource concepts with an actual
// owner. Snapshot APIs are lifecycle operations, not CloudFormation resource types.
// DocumentDB has no implemented subnet/parameter-group owner; those types are not
// aliases for an unrelated RDS resource.
func CloudFormationRelationalHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::RDS::DBInstance":              cfnRDSInstance{commands},
		"AWS::RDS::DBCluster":               cfnRDSCluster{commands},
		"AWS::RDS::DBSubnetGroup":           cfnRDSSubnetGroup{commands},
		"AWS::RDS::DBParameterGroup":        cfnRDSParameterGroup{commands},
		"AWS::RDS::DBClusterParameterGroup": cfnRDSClusterParameterGroup{commands},
		"AWS::DocDB::DBInstance":            cfnDocDBInstance{commands},
		"AWS::DocDB::DBCluster":             cfnDocDBCluster{commands},
	}
}

func cfnRDSName(r cloudformation.ResourceRequest, property string, limit int) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	if name := cfnComputeString(r.Properties, property); name != "" {
		return strings.ToLower(name)
	}
	// RDS identifiers cannot start with a digit, end in '-', or contain '--'.
	generated := strings.ToLower(cfnComputeName(r, property, limit))
	parts := strings.FieldsFunc(generated, func(ch rune) bool { return ch == '-' })
	name := strings.Join(parts, "-")
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "db-" + name
	}
	if len(name) > limit {
		name = name[len(name)-limit:]
		if name[0] < 'a' || name[0] > 'z' {
			name = "db-" + name[3:]
		}
	}
	return name
}

func cfnRDSMissing(err error) bool {
	var wire *awswire.Error
	if !errors.As(err, &wire) {
		return false
	}
	switch wire.Code {
	case "DBInstanceNotFound", "DBInstanceNotFoundFault", "DBClusterNotFoundFault", "DBParameterGroupNotFound", "DBParameterGroupNotFoundFault", "DBSubnetGroupNotFoundFault", "DBSnapshotNotFound", "DBSnapshotNotFoundFault", "DBClusterSnapshotNotFoundFault":
		return true
	}
	return false
}
func cfnRDSAbsent(err error) error {
	if cfnRDSMissing(err) {
		return nil
	}
	return err
}
func cfnRelationalContext(ctx context.Context, r cloudformation.ResourceRequest, service, kind, property string, limit int, creating bool) context.Context {
	if r.CloudControl && !creating {
		return ctx
	}
	name := cfnRDSName(r, property, limit)
	if service == "docdb" {
		return docdb.WithCloudFormationOwner(ctx, kind, name, docdb.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
	}
	// RDS's shared Query endpoint may route to the actual DocumentDB owner.
	ctx = docdb.WithCloudFormationOwner(ctx, kind, name, docdb.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
	return rds.WithCloudFormationOwner(ctx, kind, name, rds.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}
func cfnRDSPublicTags(r cloudformation.ResourceRequest) map[string]string {
	tags := maps.Clone(r.Tags)
	if tags == nil {
		tags = map[string]string{}
	}
	resource, _ := cfnComputeTags(r.Properties)
	maps.Copy(tags, resource)
	return tags
}
func cfnRDSTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.TagListMessage](ctx, c, "rds", "ListTagsForResource", map[string]any{"ResourceName": arn})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.TagList))
	for _, tag := range out.TagList {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func cfnRDSUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnRDSPublicTags(r)
	if maps.Equal(current, desired) {
		return nil
	}
	if removed := cfnComputeRemovedTags(current, desired); len(removed) != 0 {
		if err := cfnComputeRun(ctx, c, "rds", "RemoveTagsFromResource", map[string]any{"ResourceName": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "rds", "AddTagsToResource", map[string]any{"ResourceName": arn, "Tags": cfnComputeTagList(desired)})
}
func cfnRDSBooleans(p cloudformation.Properties, keys ...string) error {
	for _, key := range keys {
		if value, found := p[key]; found {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	return nil
}
func cfnRDSInteger(value any, key string) (int64, error) {
	switch v := value.(type) {
	case string:
		n, err := strconv.ParseInt(v, 10, 32)
		if err == nil {
			return n, nil
		}
	case json.Number:
		n, err := v.Int64()
		if err == nil && n >= math.MinInt32 && n <= math.MaxInt32 {
			return n, nil
		}
	case float64:
		if v >= math.MinInt32 && v <= math.MaxInt32 && math.Trunc(v) == v {
			return int64(v), nil
		}
	case int:
		if int64(v) >= math.MinInt32 && int64(v) <= math.MaxInt32 {
			return int64(v), nil
		}
	case int64:
		if v >= math.MinInt32 && v <= math.MaxInt32 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%s must be an integer within the supported range", key)
}
func cfnRDSPort(p cloudformation.Properties, input map[string]any) error {
	if value, found := p["Port"]; found {
		n, err := cfnRDSInteger(value, "Port")
		if err != nil {
			return err
		}
		if n < 1150 || n > 65535 {
			return fmt.Errorf("property Port must be between 1150 and 65535")
		}
		input["Port"] = n
	}
	return nil
}

// Unsupported native transitions are checked against the owner, not the failed
// template in Previous. An omitted class/version leaves snapshot/default engine
// selection unconstrained; an explicit value must already be the live value.
func cfnRDSImmutableString(r cloudformation.ResourceRequest, key, current string) error {
	if desired, supplied := r.Properties[key]; supplied && desired != current {
		return fmt.Errorf("native database %s modification is not implemented", key)
	}
	return nil
}

func cfnRDSImmutablePort(ctx context.Context, c StepFunctionsCommands, service, kind, name string, p cloudformation.Properties) error {
	provider, ok := c.providers[service]
	if !ok {
		return fmt.Errorf("%s database owner unavailable", service)
	}
	owner, ok := provider.executor.(interface {
		CloudFormationRequestedPort(context.Context, string, string) (int32, error)
	})
	if !ok {
		return fmt.Errorf("%s database port authority unavailable", service)
	}
	current, err := owner.CloudFormationRequestedPort(ctx, kind, name)
	if err != nil {
		return err
	}
	desired := int64(0)
	if value, supplied := p["Port"]; supplied {
		desired, err = cfnRDSInteger(value, "Port")
		if err != nil {
			return err
		}
	}
	if desired != int64(current) {
		return fmt.Errorf("native database Port modification is not implemented")
	}
	return nil
}

func cfnRDSCurrentBool[T ~bool](value *T) bool { return value != nil && bool(*value) }

func cfnRDSCreateFailure(ctx context.Context, r cloudformation.ResourceRequest, owner cloudformation.ResourceCreationRecoverer, cause error) (cloudformation.ResourceResult, error) {
	result, err := owner.RecoverCreation(ctx, r)
	if err == nil {
		return result, cause
	}
	if cfnRDSMissing(err) {
		return cloudformation.ResourceResult{}, cause
	}
	return cloudformation.ResourceResult{}, errors.Join(cause, err)
}
func cfnRDSReady(status string) (bool, error) {
	switch status {
	case "available":
		return true, nil
	case "failed", "incompatible-restore", "incompatible-parameters", "inaccessible-encryption-credentials", "storage-full":
		return false, fmt.Errorf("database owner entered terminal status %s", status)
	case "deleting", "deleted":
		return false, fmt.Errorf("database owner is being deleted")
	}
	return false, nil
}
func cfnRDSValidateDeletionPolicy(policy string) error {
	switch policy {
	case "", "Delete", "Retain", "RetainExceptOnCreate", "Snapshot":
		return nil
	}
	return fmt.Errorf("unsupported database deletion policy %s", policy)
}
