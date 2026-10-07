package integrations

import (
	"context"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/rds"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html
// A cluster is the real credential/data owner. Its DBInstance writer is a separate
// resource: publishing the cluster shell must not wait on that dependent resource.
type cfnRDSCluster struct{ commands StepFunctionsCommands }

func (h cfnRDSCluster) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DBClusterIdentifier", "Engine", "EngineVersion", "EngineMode", "DatabaseName", "MasterUsername", "MasterUserPassword", "DBClusterParameterGroupName", "Port", "DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint", "SnapshotIdentifier", "DeleteAutomatedBackups", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "ManageMasterUserPassword", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "DBClusterIdentifier", "Engine", "EngineVersion", "EngineMode", "DatabaseName", "MasterUsername", "MasterUserPassword", "DBClusterParameterGroupName", "SnapshotIdentifier"); err != nil {
		return err
	}
	if err := cfnRDSBooleans(p, "DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint", "DeleteAutomatedBackups", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "ManageMasterUserPassword"); err != nil {
		return err
	}
	for _, key := range []string{"StorageEncrypted", "EnableIAMDatabaseAuthentication", "ManageMasterUserPassword"} {
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
func (h cfnRDSCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DBClusterIdentifier", "Engine", "EngineMode", "DatabaseName", "MasterUsername", "SnapshotIdentifier"), h.Validate(b)
}
func (h cfnRDSCluster) get(ctx context.Context, name string) (*api.DBCluster, error) {
	out, err := cfnComputeCall[api.DBClusterMessage](ctx, h.commands, "rds", "DescribeDBClusters", map[string]any{"DBClusterIdentifier": name})
	if err != nil {
		return nil, err
	}
	if len(out.DBClusters) != 1 {
		return nil, fmt.Errorf("RDS returned no cluster for %s", name)
	}
	return &out.DBClusters[0], nil
}
func cfnRDSClusterResult(v *api.DBCluster) cloudformation.ResourceResult {
	id := cfnComputeValue(v.DBClusterIdentifier)
	a := map[string]any{"DBClusterArn": cfnComputeValue(v.DBClusterArn), "DBClusterResourceId": cfnComputeValue(v.DbClusterResourceId)}
	if v.Endpoint != nil {
		a["Endpoint.Address"] = cfnComputeValue(v.Endpoint)
	}
	if v.Port != nil {
		a["Endpoint.Port"] = strconv.FormatInt(int64(*v.Port), 10)
	}
	if v.ReaderEndpoint != nil {
		a["ReadEndpoint.Address"] = cfnComputeValue(v.ReaderEndpoint)
		if v.Port != nil {
			a["ReadEndpoint.Port"] = strconv.FormatInt(int64(*v.Port), 10)
		}
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: a}
}
func (h cfnRDSCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (result cloudformation.ResourceResult, err error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "cluster", "DBClusterIdentifier", 63, true)
	defer func() {
		if err != nil && result.PhysicalID == "" {
			result, err = cfnRDSCreateFailure(ctx, r, h, err)
		}
	}()
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.Properties["SnapshotIdentifier"] == nil {
		if err := cfnComputeRequired(r.Properties, "Engine"); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	} else if r.Properties["MasterUsername"] != nil || r.Properties["MasterUserPassword"] != nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("snapshot creation preserves credentials; modify the restored cluster after its writer is available")
	}
	name := cfnRDSName(r, "DBClusterIdentifier", 63)
	v, err := h.get(ctx, name)
	if err == nil {
		result := cfnRDSClusterResult(v)
		if err := cfnRDSImmutableString(r, "EngineVersion", cfnComputeValue(v.EngineVersion)); err != nil {
			return result, err
		}
		if err := cfnRDSImmutablePort(ctx, h.commands, "rds", "cluster", name, r.Properties); err != nil {
			return result, err
		}
		if r.Properties["SnapshotIdentifier"] != nil && r.Properties["EnableHttpEndpoint"] == true && (v.HttpEndpointEnabled == nil || !bool(*v.HttpEndpointEnabled)) {
			return cfnRDSClusterResult(v), cfnComputeRun(ctx, h.commands, "rds", "EnableHttpEndpoint", map[string]any{"ResourceArn": cfnComputeValue(v.DBClusterArn)})
		}
		return cfnRDSClusterResult(v), nil
	}
	if !cfnRDSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Engine", "EngineVersion", "EngineMode", "DatabaseName", "MasterUsername", "MasterUserPassword", "DBClusterParameterGroupName", "DeletionProtection", "CopyTagsToSnapshot", "EnableHttpEndpoint", "StorageEncrypted", "EnableIAMDatabaseAuthentication", "ManageMasterUserPassword")
	input["DBClusterIdentifier"], input["Tags"] = name, cfnComputeTagList(cfnRDSPublicTags(r))
	if err := cfnRDSPort(r.Properties, input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if snapshot := r.Properties["SnapshotIdentifier"]; snapshot != nil {
		input["SnapshotIdentifier"] = snapshot
		if input["Engine"] == nil {
			snapshots, err := cfnComputeCall[api.DBClusterSnapshotMessage](ctx, h.commands, "rds", "DescribeDBClusterSnapshots", map[string]any{"DBClusterSnapshotIdentifier": snapshot})
			if err != nil {
				return cloudformation.ResourceResult{}, err
			}
			if len(snapshots.DBClusterSnapshots) != 1 || cfnComputeValue(snapshots.DBClusterSnapshots[0].Engine) == "" {
				return cloudformation.ResourceResult{}, fmt.Errorf("RDS returned no snapshot engine")
			}
			input["Engine"] = cfnComputeValue(snapshots.DBClusterSnapshots[0].Engine)
		}
		// The restore operation has no HttpEndpoint switch. Apply it through
		// the actual cluster control after the restore shell exists.
		delete(input, "EnableHttpEndpoint")
		out, err := cfnComputeCall[api.RestoreDBClusterFromSnapshotResult](ctx, h.commands, "rds", "RestoreDBClusterFromSnapshot", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if out.DBCluster == nil {
			return cloudformation.ResourceResult{}, fmt.Errorf("RDS restore returned no cluster")
		}
		result := cfnRDSClusterResult(out.DBCluster)
		if r.Properties["EnableHttpEndpoint"] == true {
			return result, cfnComputeRun(ctx, h.commands, "rds", "EnableHttpEndpoint", map[string]any{"ResourceArn": cfnComputeValue(out.DBCluster.DBClusterArn)})
		}
		return result, nil
	}
	out, err := cfnComputeCall[api.CreateDBClusterResult](ctx, h.commands, "rds", "CreateDBCluster", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.DBCluster == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("RDS create returned no cluster")
	}
	return cfnRDSClusterResult(out.DBCluster), nil
}
func (h cfnRDSCluster) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "cluster", "DBClusterIdentifier", 63, true)
	v, err := h.get(ctx, cfnRDSName(r, "DBClusterIdentifier", 63))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRDSClusterResult(v), nil
}
func (h cfnRDSCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "cluster", "DBClusterIdentifier", 63, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnRDSClusterResult(v)
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBClusterArn))
	if err != nil {
		return result, err
	}

	if err := cfnRDSImmutableString(r, "EngineVersion", cfnComputeValue(v.EngineVersion)); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Port") {
		if err := cfnRDSImmutablePort(ctx, h.commands, "rds", "cluster", r.PhysicalID, r.Properties); err != nil {
			return result, err
		}
	}
	if err := cfnRDSUpdateTags(ctx, h.commands, r, cfnComputeValue(v.DBClusterArn), tags); err != nil {
		return result, err
	}
	input := map[string]any{"DBClusterIdentifier": r.PhysicalID, "ApplyImmediately": true}
	if cfnComputeChanged(r.Previous, r.Properties, "MasterUserPassword") && r.Properties["MasterUserPassword"] != nil {
		input["MasterUserPassword"] = r.Properties["MasterUserPassword"]
	}
	if desired := cfnComputeString(r.Properties, "DBClusterParameterGroupName"); desired != cfnComputeValue(v.DBClusterParameterGroup) {
		input["DBClusterParameterGroupName"] = desired
	}
	if desired := cfnComputeDefault(r.Properties, "DeletionProtection", false); desired != cfnRDSCurrentBool(v.DeletionProtection) {
		input["DeletionProtection"] = desired
	}
	if desired := cfnComputeDefault(r.Properties, "CopyTagsToSnapshot", false); desired != cfnRDSCurrentBool(v.CopyTagsToSnapshot) {
		input["CopyTagsToSnapshot"] = desired
	}
	if desired := cfnComputeDefault(r.Properties, "EnableHttpEndpoint", false); desired != cfnRDSCurrentBool(v.HttpEndpointEnabled) {
		input["EnableHttpEndpoint"] = desired
	}
	if len(input) == 2 {
		return result, nil
	}
	out, err := cfnComputeCall[api.ModifyDBClusterResult](ctx, h.commands, "rds", "ModifyDBCluster", input)
	if err != nil {
		return result, err
	}
	if out.DBCluster == nil {
		return result, fmt.Errorf("RDS modify returned no cluster")
	}
	return cfnRDSClusterResult(out.DBCluster), nil
}
func (h cfnRDSCluster) ValidateDeletionPolicy(policy string) error {
	return cfnRDSValidateDeletionPolicy(policy)
}
func (h cfnRDSCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.delete(ctx, r)
	return err
}
func (h cfnRDSCluster) delete(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "cluster", "DBClusterIdentifier", 63, false)
	name := cfnRDSName(r, "DBClusterIdentifier", 63)
	v, err := h.get(ctx, name)
	if cfnRDSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBClusterArn))
	if err != nil {
		return false, err
	}

	if cfnComputeValue(v.Status) == "deleting" {
		return false, nil
	}
	if v.DeletionProtection != nil && bool(*v.DeletionProtection) {
		return false, fmt.Errorf("cluster deletion protection is enabled")
	}
	if r.DeletionPolicy == "Snapshot" || r.DeletionPolicy == "" && !r.CloudControl {
		ready, err := cfnRDSFinalSnapshot(ctx, h.commands, r, name, cfnComputeValue(v.DbClusterResourceId), true, v.CopyTagsToSnapshot != nil && bool(*v.CopyTagsToSnapshot), tags)
		if err != nil || !ready {
			return false, err
		}
	}
	input := map[string]any{"DBClusterIdentifier": name, "SkipFinalSnapshot": true}
	if value, found := r.Properties["DeleteAutomatedBackups"]; found {
		input["DeleteAutomatedBackups"] = value
	}
	err = cfnComputeRun(ctx, h.commands, "rds", "DeleteDBCluster", input)
	return cfnRDSMissing(err), cfnRDSAbsent(err)
}
func (h cfnRDSCluster) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	return h.delete(ctx, r)
}
func (h cfnRDSCluster) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "cluster", "DBClusterIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if len(v.DBClusterMembers) == 0 && cfnComputeValue(v.Status) == "creating" {
		return true, nil
	}
	return cfnRDSReady(cfnComputeValue(v.Status))
}
func (h cfnRDSCluster) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "rds", "cluster", "DBClusterIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnRDSClusterResult(v), nil
}
func (h cfnRDSCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DBClusterIdentifier": cfnComputeValue(v.DBClusterIdentifier), "DBClusterArn": cfnComputeValue(v.DBClusterArn), "DBClusterResourceId": cfnComputeValue(v.DbClusterResourceId), "Engine": cfnComputeValue(v.Engine), "EngineVersion": cfnComputeValue(v.EngineVersion), "EngineMode": cfnComputeValue(v.EngineMode), "MasterUsername": cfnComputeValue(v.MasterUsername)}
	if v.DatabaseName != nil {
		p["DatabaseName"] = cfnComputeValue(v.DatabaseName)
	}
	if v.DBClusterParameterGroup != nil {
		p["DBClusterParameterGroupName"] = cfnComputeValue(v.DBClusterParameterGroup)
	}
	if v.DeletionProtection != nil {
		p["DeletionProtection"] = bool(*v.DeletionProtection)
	}
	if v.CopyTagsToSnapshot != nil {
		p["CopyTagsToSnapshot"] = bool(*v.CopyTagsToSnapshot)
	}
	if v.HttpEndpointEnabled != nil {
		p["EnableHttpEndpoint"] = bool(*v.HttpEndpointEnabled)
	}
	if v.Endpoint != nil {
		p["Endpoint"] = map[string]any{"Address": cfnComputeValue(v.Endpoint)}
	}
	if v.Port != nil {
		p["Port"] = int64(*v.Port)
		if endpoint, ok := p["Endpoint"].(map[string]any); ok {
			endpoint["Port"] = strconv.FormatInt(int64(*v.Port), 10)
		}
	}
	if v.ReaderEndpoint != nil {
		endpoint := map[string]any{"Address": cfnComputeValue(v.ReaderEndpoint)}
		if v.Port != nil {
			endpoint["Port"] = strconv.FormatInt(int64(*v.Port), 10)
		}
		p["ReadEndpoint"] = endpoint
	}
	tags, err := cfnRDSTags(ctx, h.commands, cfnComputeValue(v.DBClusterArn))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnRDSCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DBClusterMessage](ctx, h.commands, "rds", "DescribeDBClusters", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.DBClusters {
			r.PhysicalID = cfnComputeValue(v.DBClusterIdentifier)
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
