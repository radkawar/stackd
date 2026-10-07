package integrations

import (
	"context"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/rds"
	"stackd/internal/services/cloudformation"
)

// Lifecycle and attributes follow the official DBInstance resource contract:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html
// Native-engine/storage limits remain enforced by the ordinary RDS owner.
type cfnRDSInstance struct{ commands StepFunctionsCommands }

func (h cfnRDSInstance) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DBInstanceIdentifier", "DBInstanceClass", "DBClusterIdentifier", "Engine", "EngineVersion", "DBName", "MasterUsername", "MasterUserPassword", "DBParameterGroupName", "Port", "DeletionProtection", "CopyTagsToSnapshot", "DBSnapshotIdentifier", "DeleteAutomatedBackups", "AutoMinorVersionUpgrade", "MultiAZ", "PubliclyAccessible", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "EnablePerformanceInsights", "ManageMasterUserPassword", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "DBInstanceIdentifier", "DBInstanceClass", "DBClusterIdentifier", "Engine", "EngineVersion", "DBName", "MasterUsername", "MasterUserPassword", "DBParameterGroupName", "DBSnapshotIdentifier"); err != nil {
		return err
	}
	if err := cfnRDSBooleans(p, "DeletionProtection", "CopyTagsToSnapshot", "DeleteAutomatedBackups", "AutoMinorVersionUpgrade", "MultiAZ", "PubliclyAccessible", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "EnablePerformanceInsights", "ManageMasterUserPassword"); err != nil {
		return err
	}
	for _, key := range []string{"AutoMinorVersionUpgrade", "MultiAZ", "PubliclyAccessible", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "EnablePerformanceInsights", "ManageMasterUserPassword"} {
		if p[key] == true {
			return fmt.Errorf("%s is not implemented by the native database owner", key)
		}
	}
	if p["DeleteAutomatedBackups"] == false {
		return fmt.Errorf("retained automated backups are not implemented by the native database owner")
	}
	if err := cfnRDSPort(p, map[string]any{}); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnRDSInstance) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	// Removing the restore hint does not destroy an already restored instance.
	snapshotChanged := b["DBSnapshotIdentifier"] != nil && cfnComputeChanged(a, b, "DBSnapshotIdentifier")
	return snapshotChanged || cfnComputeChanged(a, b, "DBInstanceIdentifier", "DBClusterIdentifier", "DBName", "MasterUsername", "Engine"), nil
}
func (h cfnRDSInstance) get(ctx context.Context, name string) (*api.DBInstance, error) {
	out, err := cfnComputeCall[api.DBInstanceMessage](ctx, h.commands, "rds", "DescribeDBInstances", map[string]any{"DBInstanceIdentifier": name})
	if err != nil {
		return nil, err
	}
	if len(out.DBInstances) != 1 {
		return nil, fmt.Errorf("RDS returned no instance for %s", name)
	}
	return &out.DBInstances[0], nil
}
func cfnRDSInstanceResult(v *api.DBInstance) cloudformation.ResourceResult {
	id := cfnComputeValue(v.DBInstanceIdentifier)
	a := map[string]any{"DBInstanceArn": cfnComputeValue(v.DBInstanceArn), "DbiResourceId": cfnComputeValue(v.DbiResourceId), "DBInstanceStatus": cfnComputeValue(v.DBInstanceStatus)}
	if v.Endpoint != nil {
		a["Endpoint.Address"] = cfnComputeValue(v.Endpoint.Address)
		if v.Endpoint.Port != nil {
			a["Endpoint.Port"] = strconv.FormatInt(int64(*v.Endpoint.Port), 10)
		}
		if v.Endpoint.HostedZoneId != nil {
			a["Endpoint.HostedZoneId"] = cfnComputeValue(v.Endpoint.HostedZoneId)
		}
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: a}
}
func (h cfnRDSInstance) Create(ctx context.Context, r cloudformation.ResourceRequest) (result cloudformation.ResourceResult, err error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "db", "DBInstanceIdentifier", 63, true)
	defer func() {
		if err != nil && result.PhysicalID == "" {
			result, err = cfnRDSCreateFailure(ctx, r, h, err)
		}
	}()
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.Properties["DBSnapshotIdentifier"] == nil {
		if err := cfnComputeRequired(r.Properties, "Engine", "DBInstanceClass"); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	} else {
		for _, key := range []string{"MasterUsername", "MasterUserPassword", "DBClusterIdentifier", "EngineVersion"} {
			if r.Properties[key] != nil {
				return cloudformation.ResourceResult{}, fmt.Errorf("%s cannot be supplied when creating from DBSnapshotIdentifier", key)
			}
		}
	}
	name := cfnRDSName(r, "DBInstanceIdentifier", 63)
	v, err := h.get(ctx, name)
	if err == nil {
		result := cfnRDSInstanceResult(v)
		if err := cfnRDSImmutableString(r, "DBInstanceClass", cfnComputeValue(v.DBInstanceClass)); err != nil {
			return result, err
		}
		if err := cfnRDSImmutableString(r, "EngineVersion", cfnComputeValue(v.EngineVersion)); err != nil {
			return result, err
		}
		if err := cfnRDSImmutablePort(ctx, h.commands, "rds", "db", name, r.Properties); err != nil {
			return result, err
		}
		return cfnRDSInstanceResult(v), nil
	}
	if !cfnRDSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "DBInstanceClass", "DBClusterIdentifier", "Engine", "EngineVersion", "DBName", "MasterUsername", "MasterUserPassword", "DBParameterGroupName", "DeletionProtection", "CopyTagsToSnapshot", "AutoMinorVersionUpgrade", "MultiAZ", "PubliclyAccessible", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "EnablePerformanceInsights", "ManageMasterUserPassword")
	input["DBInstanceIdentifier"], input["Tags"] = name, cfnComputeTagList(cfnRDSPublicTags(r))
	if err := cfnRDSPort(r.Properties, input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if snapshot := r.Properties["DBSnapshotIdentifier"]; snapshot != nil {
		input["DBSnapshotIdentifier"] = snapshot
		out, err := cfnComputeCall[api.RestoreDBInstanceFromDBSnapshotResult](ctx, h.commands, "rds", "RestoreDBInstanceFromDBSnapshot", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if out.DBInstance == nil {
			return cloudformation.ResourceResult{}, fmt.Errorf("RDS restore returned no instance")
		}
		return cfnRDSInstanceResult(out.DBInstance), nil
	}
	out, err := cfnComputeCall[api.CreateDBInstanceResult](ctx, h.commands, "rds", "CreateDBInstance", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.DBInstance == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("RDS create returned no instance")
	}
	return cfnRDSInstanceResult(out.DBInstance), nil
}
func (h cfnRDSInstance) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "db", "DBInstanceIdentifier", 63, true)
	v, err := h.get(ctx, cfnRDSName(r, "DBInstanceIdentifier", 63))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRDSInstanceResult(v), nil
}
func (h cfnRDSInstance) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "db", "DBInstanceIdentifier", 63, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnRDSInstanceResult(v)
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBInstanceArn))
	if err != nil {
		return result, err
	}

	if err := cfnRDSImmutableString(r, "DBInstanceClass", cfnComputeValue(v.DBInstanceClass)); err != nil {
		return result, err
	}
	if err := cfnRDSImmutableString(r, "EngineVersion", cfnComputeValue(v.EngineVersion)); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Port") {
		if err := cfnRDSImmutablePort(ctx, h.commands, "rds", "db", r.PhysicalID, r.Properties); err != nil {
			return result, err
		}
	}
	if err := cfnRDSUpdateTags(ctx, h.commands, r, cfnComputeValue(v.DBInstanceArn), tags); err != nil {
		return result, err
	}
	input := map[string]any{"DBInstanceIdentifier": r.PhysicalID, "ApplyImmediately": true}
	if cfnComputeChanged(r.Previous, r.Properties, "MasterUserPassword") && r.Properties["MasterUserPassword"] != nil {
		input["MasterUserPassword"] = r.Properties["MasterUserPassword"]
	}
	group := ""
	if len(v.DBParameterGroups) == 1 {
		group = cfnComputeValue(v.DBParameterGroups[0].DBParameterGroupName)
	}
	if desired := cfnComputeString(r.Properties, "DBParameterGroupName"); desired != group {
		input["DBParameterGroupName"] = desired
	}
	if desired := cfnComputeDefault(r.Properties, "DeletionProtection", false); desired != cfnRDSCurrentBool(v.DeletionProtection) {
		input["DeletionProtection"] = desired
	}
	if desired := cfnComputeDefault(r.Properties, "CopyTagsToSnapshot", false); desired != cfnRDSCurrentBool(v.CopyTagsToSnapshot) {
		input["CopyTagsToSnapshot"] = desired
	}
	if len(input) == 2 {
		return result, nil
	}
	out, err := cfnComputeCall[api.ModifyDBInstanceResult](ctx, h.commands, "rds", "ModifyDBInstance", input)
	if err != nil {
		return result, err
	}
	if out.DBInstance == nil {
		return result, fmt.Errorf("RDS modify returned no instance")
	}
	return cfnRDSInstanceResult(out.DBInstance), nil
}
func (h cfnRDSInstance) ValidateDeletionPolicy(policy string) error {
	return cfnRDSValidateDeletionPolicy(policy)
}
func (h cfnRDSInstance) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.delete(ctx, r)
	return err
}
func (h cfnRDSInstance) delete(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "db", "DBInstanceIdentifier", 63, false)
	name := cfnRDSName(r, "DBInstanceIdentifier", 63)
	v, err := h.get(ctx, name)
	if cfnRDSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBInstanceArn))
	if err != nil {
		return false, err
	}

	if cfnComputeValue(v.DBInstanceStatus) == "deleting" {
		return false, nil
	}
	if v.DeletionProtection != nil && bool(*v.DeletionProtection) {
		return false, fmt.Errorf("database deletion protection is enabled")
	}
	snapshot := r.DeletionPolicy == "Snapshot" || r.DeletionPolicy == "" && !r.CloudControl && cfnComputeValue(v.DBClusterIdentifier) == ""
	if snapshot {
		if cfnComputeValue(v.DBClusterIdentifier) != "" {
			return false, fmt.Errorf("snapshot the owning cluster, not its writer instance")
		}
		ready, err := cfnRDSFinalSnapshot(ctx, h.commands, r, name, cfnComputeValue(v.DbiResourceId), false, v.CopyTagsToSnapshot != nil && bool(*v.CopyTagsToSnapshot), tags)
		if err != nil || !ready {
			return false, err
		}
	}
	input := map[string]any{"DBInstanceIdentifier": name, "SkipFinalSnapshot": true}
	if value, found := r.Properties["DeleteAutomatedBackups"]; found {
		input["DeleteAutomatedBackups"] = value
	}
	err = cfnComputeRun(ctx, h.commands, "rds", "DeleteDBInstance", input)
	return cfnRDSMissing(err), cfnRDSAbsent(err)
}
func (h cfnRDSInstance) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	return h.delete(ctx, r)
}
func (h cfnRDSInstance) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "db", "DBInstanceIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnRDSReady(cfnComputeValue(v.DBInstanceStatus))
}
func (h cfnRDSInstance) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "db", "DBInstanceIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRDSInstanceResult(v), nil
}
func (h cfnRDSInstance) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DBInstanceIdentifier": cfnComputeValue(v.DBInstanceIdentifier), "DBInstanceArn": cfnComputeValue(v.DBInstanceArn), "DbiResourceId": cfnComputeValue(v.DbiResourceId), "DBInstanceStatus": cfnComputeValue(v.DBInstanceStatus), "DBInstanceClass": cfnComputeValue(v.DBInstanceClass), "Engine": cfnComputeValue(v.Engine), "EngineVersion": cfnComputeValue(v.EngineVersion), "MasterUsername": cfnComputeValue(v.MasterUsername)}
	if v.DBName != nil {
		p["DBName"] = cfnComputeValue(v.DBName)
	}
	if v.DBClusterIdentifier != nil {
		p["DBClusterIdentifier"] = cfnComputeValue(v.DBClusterIdentifier)
	}
	if v.DeletionProtection != nil {
		p["DeletionProtection"] = bool(*v.DeletionProtection)
	}
	if v.CopyTagsToSnapshot != nil {
		p["CopyTagsToSnapshot"] = bool(*v.CopyTagsToSnapshot)
	}
	if len(v.DBParameterGroups) == 1 {
		p["DBParameterGroupName"] = cfnComputeValue(v.DBParameterGroups[0].DBParameterGroupName)
	}
	if v.Endpoint != nil {
		endpoint := map[string]any{"Address": cfnComputeValue(v.Endpoint.Address)}
		if v.Endpoint.Port != nil {
			endpoint["Port"] = strconv.FormatInt(int64(*v.Endpoint.Port), 10)
			p["Port"] = int64(*v.Endpoint.Port)
		}
		p["Endpoint"] = endpoint
	}
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBInstanceArn))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnRDSInstance) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DBInstanceMessage](ctx, h.commands, "rds", "DescribeDBInstances", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.DBInstances {
			r.PhysicalID = cfnComputeValue(v.DBInstanceIdentifier)
			p, err := h.Read(ctx, r)
			if err != nil {
				if cfnRDSMissing(err) {
					continue
				}
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if marker := cfnComputeValue(out.Marker); marker != "" {
			input["Marker"] = marker
		} else {
			return rows, nil
		}
	}
}
