package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/rds"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/docdb"
	"stackd/internal/services/rds"
)

func cfnRDSFinalSnapshotName(r cloudformation.ResourceRequest, source string) string {
	return "cfn-final-" + cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token+"/"+source)
}

// Snapshot policy is a real service-owned backup followed by ordinary deletion.
// Its private native controller/source claims survive controller restart; no
// public tags or retained CFN copy can certify that a backup actually completed.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html
func cfnRDSFinalSnapshot(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, source, incarnation string, cluster, copyTags bool, sourceTags map[string]string) (bool, error) {
	name := cfnRDSFinalSnapshotName(r, source)
	kind, sourceKind := "snapshot", "db"
	if cluster {
		kind, sourceKind = "cluster-snapshot", "cluster"
	}
	ctx = rds.WithCloudFormationSnapshot(ctx, kind, name, sourceKind, source, incarnation, rds.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, !r.CloudControl)
	if cluster {
		ctx = docdb.WithCloudFormationSnapshot(ctx, name, source, incarnation, docdb.CloudFormationOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}, !r.CloudControl)
	}
	var status, actualSource, actualIncarnation string
	var err error
	if cluster {
		var out *api.DBClusterSnapshotMessage
		out, err = cfnComputeCall[api.DBClusterSnapshotMessage](ctx, c, "rds", "DescribeDBClusterSnapshots", map[string]any{"DBClusterSnapshotIdentifier": name})
		if err == nil {
			if len(out.DBClusterSnapshots) != 1 {
				return false, fmt.Errorf("RDS returned no final cluster snapshot")
			}
			v := out.DBClusterSnapshots[0]
			status, actualSource, actualIncarnation = cfnComputeValue(v.Status), cfnComputeValue(v.DBClusterIdentifier), cfnComputeValue(v.DbClusterResourceId)
		}
	} else {
		var out *api.DBSnapshotMessage
		out, err = cfnComputeCall[api.DBSnapshotMessage](ctx, c, "rds", "DescribeDBSnapshots", map[string]any{"DBSnapshotIdentifier": name})
		if err == nil {
			if len(out.DBSnapshots) != 1 {
				return false, fmt.Errorf("RDS returned no final instance snapshot")
			}
			v := out.DBSnapshots[0]
			status, actualSource, actualIncarnation = cfnComputeValue(v.Status), cfnComputeValue(v.DBInstanceIdentifier), cfnComputeValue(v.DbiResourceId)
		}
	}
	if err != nil && !cfnRDSMissing(err) {
		return false, err
	}
	if err == nil {
		if actualSource != source || actualIncarnation != "" && actualIncarnation != incarnation {
			return false, fmt.Errorf("final snapshot belongs to a different database incarnation")
		}
		if status == "failed" || status == "deleting" {
			return false, fmt.Errorf("final snapshot entered status %s", status)
		}
		return status == "available", nil
	}
	// Copy only customer metadata when requested. Private owner/source claims
	// commit atomically with the snapshot and fenced source lifecycle intent.
	tags := map[string]string{}
	if copyTags {
		tags = cfnRDSPublicTags(cloudformation.ResourceRequest{Tags: sourceTags})
	}
	input := map[string]any{"Tags": cfnComputeTagList(tags)}
	if cluster {
		input["DBClusterIdentifier"], input["DBClusterSnapshotIdentifier"] = source, name
		err = cfnComputeRun(ctx, c, "rds", "CreateDBClusterSnapshot", input)
	} else {
		input["DBInstanceIdentifier"], input["DBSnapshotIdentifier"] = source, name
		err = cfnComputeRun(ctx, c, "rds", "CreateDBSnapshot", input)
	}
	return false, err
}
