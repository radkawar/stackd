package integrations

import (
	"context"
	"fmt"
	"maps"
	"strconv"

	api "stackd/internal/awsapi/docdb"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/docdb"
)

// The DocumentDB adapter uses the real document owner, with its native MongoDB
// compatibility backend and explicit unsupported managed-engine controls.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-docdb-dbcluster.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-docdb-dbinstance.html
type cfnDocDBCluster struct{ commands StepFunctionsCommands }
type cfnDocDBInstance struct{ commands StepFunctionsCommands }

func cfnDocDBTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "docdb", "ListTagsForResource", map[string]any{"ResourceName": arn})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string, len(out.TagList))
	for _, tag := range out.TagList {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func cfnDocDBUpdateTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string, current map[string]string) error {
	desired := cfnRDSPublicTags(r)
	if maps.Equal(current, desired) {
		return nil
	}
	if removed := cfnComputeRemovedTags(current, desired); len(removed) != 0 {
		if err := cfnComputeRun(ctx, c, "docdb", "RemoveTagsFromResource", map[string]any{"ResourceName": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "docdb", "AddTagsToResource", map[string]any{"ResourceName": arn, "Tags": cfnComputeTagList(desired)})
}
func (h cfnDocDBCluster) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DBClusterIdentifier", "EngineVersion", "MasterUsername", "MasterUserPassword", "Port", "DeletionProtection", "SnapshotIdentifier", "StorageEncrypted", "ManageMasterUserPassword", "CopyTagsToSnapshot", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "DBClusterIdentifier", "EngineVersion", "MasterUsername", "MasterUserPassword", "SnapshotIdentifier"); err != nil {
		return err
	}
	if err := cfnRDSBooleans(p, "DeletionProtection", "StorageEncrypted", "ManageMasterUserPassword", "CopyTagsToSnapshot"); err != nil {
		return err
	}
	for _, key := range []string{"StorageEncrypted", "ManageMasterUserPassword", "CopyTagsToSnapshot"} {
		if p[key] == true {
			return fmt.Errorf("%s is not implemented by the native DocumentDB owner", key)
		}
	}
	if err := cfnRDSPort(p, map[string]any{}); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnDocDBCluster) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DBClusterIdentifier", "MasterUsername", "SnapshotIdentifier", "StorageEncrypted"), h.Validate(b)
}
func (h cfnDocDBCluster) get(ctx context.Context, name string) (*api.DBCluster, error) {
	out, err := cfnComputeCall[api.DescribeDBClustersOutput](ctx, h.commands, "docdb", "DescribeDBClusters", map[string]any{"DBClusterIdentifier": name})
	if err != nil {
		return nil, err
	}
	if len(out.DBClusters) != 1 {
		return nil, fmt.Errorf("DocumentDB returned no cluster")
	}
	return &out.DBClusters[0], nil
}
func cfnDocDBClusterResult(v *api.DBCluster) cloudformation.ResourceResult {
	id := cfnComputeValue(v.DBClusterIdentifier)
	a := map[string]any{"Id": id, "ClusterResourceId": cfnComputeValue(v.DbClusterResourceId)}
	if v.Endpoint != nil {
		a["Endpoint"] = cfnComputeValue(v.Endpoint)
	}
	if v.ReaderEndpoint != nil {
		a["ReadEndpoint"] = cfnComputeValue(v.ReaderEndpoint)
	}
	if v.Port != nil {
		a["Port"] = strconv.FormatInt(int64(*v.Port), 10)
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: a}
}
func (h cfnDocDBCluster) Create(ctx context.Context, r cloudformation.ResourceRequest) (result cloudformation.ResourceResult, err error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "cluster", "DBClusterIdentifier", 63, true)
	defer func() {
		if err != nil && result.PhysicalID == "" {
			result, err = cfnRDSCreateFailure(ctx, r, h, err)
		}
	}()
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if r.Properties["SnapshotIdentifier"] != nil && (r.Properties["MasterUsername"] != nil || r.Properties["MasterUserPassword"] != nil) {
		return cloudformation.ResourceResult{}, fmt.Errorf("snapshot creation preserves credentials; modify the restored cluster after its writer is available")
	}
	name := cfnRDSName(r, "DBClusterIdentifier", 63)
	v, err := h.get(ctx, name)
	if err == nil {
		result := cfnDocDBClusterResult(v)
		if err := cfnRDSImmutableString(r, "EngineVersion", cfnComputeValue(v.EngineVersion)); err != nil {
			return result, err
		}
		if err := cfnRDSImmutablePort(ctx, h.commands, "docdb", "cluster", name, r.Properties); err != nil {
			return result, err
		}
		return result, nil
	}
	if !cfnRDSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "EngineVersion", "MasterUsername", "MasterUserPassword", "DeletionProtection", "StorageEncrypted", "ManageMasterUserPassword")
	input["Engine"], input["DBClusterIdentifier"], input["Tags"] = "docdb", name, cfnComputeTagList(cfnRDSPublicTags(r))
	if err := cfnRDSPort(r.Properties, input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if snapshot := r.Properties["SnapshotIdentifier"]; snapshot != nil {
		input["SnapshotIdentifier"] = snapshot
		delete(input, "StorageEncrypted")
		delete(input, "ManageMasterUserPassword")
		out, err := cfnComputeCall[api.RestoreDBClusterFromSnapshotOutput](ctx, h.commands, "docdb", "RestoreDBClusterFromSnapshot", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if out.DBCluster == nil {
			return cloudformation.ResourceResult{}, fmt.Errorf("DocumentDB restore returned no cluster")
		}
		return cfnDocDBClusterResult(out.DBCluster), nil
	}
	out, err := cfnComputeCall[api.CreateDBClusterOutput](ctx, h.commands, "docdb", "CreateDBCluster", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.DBCluster == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("DocumentDB create returned no cluster")
	}
	return cfnDocDBClusterResult(out.DBCluster), nil
}
func (h cfnDocDBCluster) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "cluster", "DBClusterIdentifier", 63, true)
	v, err := h.get(ctx, cfnRDSName(r, "DBClusterIdentifier", 63))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDocDBClusterResult(v), nil
}
func (h cfnDocDBCluster) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "cluster", "DBClusterIdentifier", 63, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnDocDBClusterResult(v)
	tags, err := cfnDocDBTags(ctx, h.commands, cfnComputeValue(v.DBClusterArn))
	if err != nil {
		return result, err
	}

	if err := cfnRDSImmutableString(r, "EngineVersion", cfnComputeValue(v.EngineVersion)); err != nil {
		return result, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Port") {
		if err := cfnRDSImmutablePort(ctx, h.commands, "docdb", "cluster", r.PhysicalID, r.Properties); err != nil {
			return result, err
		}
	}
	if err := cfnDocDBUpdateTags(ctx, h.commands, r, cfnComputeValue(v.DBClusterArn), tags); err != nil {
		return result, err
	}
	input := map[string]any{"DBClusterIdentifier": r.PhysicalID, "ApplyImmediately": true}
	if cfnComputeChanged(r.Previous, r.Properties, "MasterUserPassword") && r.Properties["MasterUserPassword"] != nil {
		input["MasterUserPassword"] = r.Properties["MasterUserPassword"]
	}
	if desired := cfnComputeDefault(r.Properties, "DeletionProtection", false); desired != cfnRDSCurrentBool(v.DeletionProtection) {
		input["DeletionProtection"] = desired
	}
	if len(input) == 2 {
		return result, nil
	}
	out, err := cfnComputeCall[api.ModifyDBClusterOutput](ctx, h.commands, "docdb", "ModifyDBCluster", input)
	if err != nil {
		return result, err
	}
	if out.DBCluster == nil {
		return result, fmt.Errorf("DocumentDB modify returned no cluster")
	}
	return cfnDocDBClusterResult(out.DBCluster), nil
}
func (h cfnDocDBCluster) ValidateDeletionPolicy(policy string) error {
	return cfnRDSValidateDeletionPolicy(policy)
}
func (h cfnDocDBCluster) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.delete(ctx, r)
	return err
}
func (h cfnDocDBCluster) delete(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "cluster", "DBClusterIdentifier", 63, false)
	name := cfnRDSName(r, "DBClusterIdentifier", 63)
	v, err := h.get(ctx, name)
	if cfnRDSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if cfnComputeValue(v.Status) == "deleting" {
		return false, nil
	}
	if v.DeletionProtection != nil && bool(*v.DeletionProtection) {
		return false, fmt.Errorf("cluster deletion protection is enabled")
	}
	if r.DeletionPolicy == "Snapshot" {
		ready, err := h.finalSnapshot(ctx, r, v)
		if err != nil || !ready {
			return false, err
		}
	}
	err = cfnComputeRun(ctx, h.commands, "docdb", "DeleteDBCluster", map[string]any{"DBClusterIdentifier": name, "SkipFinalSnapshot": true})
	return cfnRDSMissing(err), cfnRDSAbsent(err)
}
func (h cfnDocDBCluster) finalSnapshot(ctx context.Context, r cloudformation.ResourceRequest, source *api.DBCluster) (bool, error) {
	sourceName, incarnation := cfnComputeValue(source.DBClusterIdentifier), cfnComputeValue(source.DbClusterResourceId)
	name := cfnRDSFinalSnapshotName(r, sourceName)
	ctx = docdb.WithCloudFormationSnapshot(ctx, name, sourceName, incarnation, docdb.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, !r.CloudControl)
	out, err := cfnComputeCall[api.DescribeDBClusterSnapshotsOutput](ctx, h.commands, "docdb", "DescribeDBClusterSnapshots", map[string]any{"DBClusterSnapshotIdentifier": name})
	if err == nil {
		if len(out.DBClusterSnapshots) != 1 {
			return false, fmt.Errorf("DocumentDB returned no final snapshot")
		}
		v := out.DBClusterSnapshots[0]
		if cfnComputeValue(v.DBClusterIdentifier) != sourceName {
			return false, fmt.Errorf("final snapshot belongs to a different cluster")
		}
		status := cfnComputeValue(v.Status)
		if status == "failed" || status == "deleting" {
			return false, fmt.Errorf("final snapshot entered status %s", status)
		}
		return status == "available", nil
	}
	if !cfnRDSMissing(err) {
		return false, err
	}
	// The snapshot owner commits its private controller and source-incarnation
	// claims with the real native backup intent; no tag can counterfeit them.
	return false, cfnComputeRun(ctx, h.commands, "docdb", "CreateDBClusterSnapshot", map[string]any{"DBClusterIdentifier": sourceName, "DBClusterSnapshotIdentifier": name})
}
func (h cfnDocDBCluster) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	return h.delete(ctx, r)
}
func (h cfnDocDBCluster) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "cluster", "DBClusterIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if len(v.DBClusterMembers) == 0 && cfnComputeValue(v.Status) == "creating" {
		return true, nil
	}
	return cfnRDSReady(cfnComputeValue(v.Status))
}
func (h cfnDocDBCluster) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "cluster", "DBClusterIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDocDBClusterResult(v), nil
}
func (h cfnDocDBCluster) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DBClusterIdentifier": cfnComputeValue(v.DBClusterIdentifier), "Id": cfnComputeValue(v.DBClusterIdentifier), "ClusterResourceId": cfnComputeValue(v.DbClusterResourceId), "EngineVersion": cfnComputeValue(v.EngineVersion), "MasterUsername": cfnComputeValue(v.MasterUsername)}
	if v.DeletionProtection != nil {
		p["DeletionProtection"] = bool(*v.DeletionProtection)
	}
	if v.Endpoint != nil {
		p["Endpoint"] = cfnComputeValue(v.Endpoint)
	}
	if v.ReaderEndpoint != nil {
		p["ReadEndpoint"] = cfnComputeValue(v.ReaderEndpoint)
	}
	if v.Port != nil {
		p["Port"] = int64(*v.Port)
	}
	tags, err := cfnDocDBTags(ctx, h.commands, cfnComputeValue(v.DBClusterArn))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnDocDBCluster) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeDBClustersOutput](ctx, h.commands, "docdb", "DescribeDBClusters", input)
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
func (h cfnDocDBInstance) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DBInstanceIdentifier", "DBInstanceClass", "DBClusterIdentifier", "AutoMinorVersionUpgrade", "EnablePerformanceInsights", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "DBInstanceClass", "DBClusterIdentifier"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "DBInstanceIdentifier", "DBInstanceClass", "DBClusterIdentifier"); err != nil {
		return err
	}
	if err := cfnRDSBooleans(p, "AutoMinorVersionUpgrade", "EnablePerformanceInsights"); err != nil {
		return err
	}
	for _, key := range []string{"AutoMinorVersionUpgrade", "EnablePerformanceInsights"} {
		if p[key] == true {
			return fmt.Errorf("%s is not implemented by the native DocumentDB owner", key)
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnDocDBInstance) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DBInstanceIdentifier", "DBClusterIdentifier"), h.Validate(b)
}
func (h cfnDocDBInstance) get(ctx context.Context, name string) (*api.DBInstance, error) {
	out, err := cfnComputeCall[api.DescribeDBInstancesOutput](ctx, h.commands, "docdb", "DescribeDBInstances", map[string]any{"DBInstanceIdentifier": name})
	if err != nil {
		return nil, err
	}
	if len(out.DBInstances) != 1 {
		return nil, fmt.Errorf("DocumentDB returned no instance")
	}
	return &out.DBInstances[0], nil
}
func cfnDocDBInstanceResult(v *api.DBInstance) cloudformation.ResourceResult {
	id := cfnComputeValue(v.DBInstanceIdentifier)
	a := map[string]any{"Id": id}
	if v.Endpoint != nil {
		a["Endpoint"] = cfnComputeValue(v.Endpoint.Address)
		if v.Endpoint.Port != nil {
			a["Port"] = strconv.FormatInt(int64(*v.Endpoint.Port), 10)
		}
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: a}
}
func (h cfnDocDBInstance) Create(ctx context.Context, r cloudformation.ResourceRequest) (result cloudformation.ResourceResult, err error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, true)
	defer func() {
		if err != nil && result.PhysicalID == "" {
			result, err = cfnRDSCreateFailure(ctx, r, h, err)
		}
	}()
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnRDSName(r, "DBInstanceIdentifier", 63)
	v, err := h.get(ctx, name)
	if err == nil {
		result := cfnDocDBInstanceResult(v)
		if err := cfnRDSImmutableString(r, "DBInstanceClass", cfnComputeValue(v.DBInstanceClass)); err != nil {
			return result, err
		}
		return result, nil
	}
	if !cfnRDSMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "DBInstanceClass", "DBClusterIdentifier", "AutoMinorVersionUpgrade", "EnablePerformanceInsights")
	input["Engine"], input["DBInstanceIdentifier"], input["Tags"] = "docdb", name, cfnComputeTagList(cfnRDSPublicTags(r))
	out, err := cfnComputeCall[api.CreateDBInstanceOutput](ctx, h.commands, "docdb", "CreateDBInstance", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.DBInstance == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("DocumentDB create returned no instance")
	}
	return cfnDocDBInstanceResult(out.DBInstance), nil
}
func (h cfnDocDBInstance) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, true)
	v, err := h.get(ctx, cfnRDSName(r, "DBInstanceIdentifier", 63))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDocDBInstanceResult(v), nil
}
func (h cfnDocDBInstance) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, false)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnDocDBInstanceResult(v)
	tags, err := cfnDocDBTags(ctx, h.commands, cfnComputeValue(v.DBInstanceArn))
	if err != nil {
		return result, err
	}

	if err := cfnRDSImmutableString(r, "DBInstanceClass", cfnComputeValue(v.DBInstanceClass)); err != nil {
		return result, err
	}
	return result, cfnDocDBUpdateTags(ctx, h.commands, r, cfnComputeValue(v.DBInstanceArn), tags)
}
func (h cfnDocDBInstance) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, false)
	name := cfnRDSName(r, "DBInstanceIdentifier", 63)
	v, err := h.get(ctx, name)
	if cfnRDSMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(v.DBInstanceStatus) == "deleting" {
		return nil
	}
	return cfnRDSAbsent(cfnComputeRun(ctx, h.commands, "docdb", "DeleteDBInstance", map[string]any{"DBInstanceIdentifier": name}))
}
func (h cfnDocDBInstance) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, false)
	_, err := h.get(ctx, cfnRDSName(r, "DBInstanceIdentifier", 63))
	if cfnRDSMissing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}
func (h cfnDocDBInstance) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	return cfnRDSReady(cfnComputeValue(v.DBInstanceStatus))
}
func (h cfnDocDBInstance) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnRelationalContext(ctx, r, "docdb", "db", "DBInstanceIdentifier", 63, false)
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnDocDBInstanceResult(v), nil
}
func (h cfnDocDBInstance) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"DBInstanceIdentifier": cfnComputeValue(v.DBInstanceIdentifier), "Id": cfnComputeValue(v.DBInstanceIdentifier), "DBInstanceClass": cfnComputeValue(v.DBInstanceClass), "DBClusterIdentifier": cfnComputeValue(v.DBClusterIdentifier), "AutoMinorVersionUpgrade": false, "EnablePerformanceInsights": false}
	if v.Endpoint != nil {
		p["Endpoint"] = cfnComputeValue(v.Endpoint.Address)
		if v.Endpoint.Port != nil {
			p["Port"] = strconv.FormatInt(int64(*v.Endpoint.Port), 10)
		}
	}
	tags, err := cfnDocDBTags(ctx, h.commands, cfnComputeValue(v.DBInstanceArn))
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnDocDBInstance) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeDBInstancesOutput](ctx, h.commands, "docdb", "DescribeDBInstances", input)
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
