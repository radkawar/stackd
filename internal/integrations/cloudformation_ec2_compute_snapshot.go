package integrations

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

const cfnEC2VolumeDeletionSnapshot = "AWS::EC2::VolumeDeletionSnapshot"

func (h cfnEC2Volume) ValidateDeletionPolicy(policy string) error {
	switch policy {
	case "", "Delete", "Retain", "RetainExceptOnCreate", "Snapshot":
		return nil
	default:
		return fmt.Errorf("unsupported EC2 Volume deletion policy %s", policy)
	}
}

// deletionSnapshot recovers the snapshot from the EBS private creation receipt
// admitted atomically with CreateSnapshot for this volume incarnation; public
// snapshot tags are customer metadata only. The volume is kept until the real
// EBS snapshot owner reports completion.
func (h cfnEC2Volume) deletionSnapshot(ctx context.Context, r cloudformation.ResourceRequest, v api.Volume) (bool, error) {
	if r.Token == "" {
		return false, fmt.Errorf("EBS deletion snapshot requires a resource incarnation")
	}
	owner, err := cfnEC2NativeOwner(h.commands)
	if err != nil {
		return false, err
	}
	identity := cfnEC2NativeIdentity(r)
	id, err := owner.CloudFormationCreation(ctx, cfnEC2VolumeDeletionSnapshot, identity)
	if errors.Is(err, ec2.ErrNotFound) {
		in := map[string]any{"VolumeId": r.PhysicalID, "Description": "CloudFormation deletion snapshot for " + r.PhysicalID}
		if tags := cfnEC2Tags(v.Tags); len(tags) != 0 {
			in["TagSpecifications"] = []any{map[string]any{"ResourceType": "snapshot", "Tags": cfnComputeTagList(tags)}}
		}
		out, e := cfnComputeCall[api.Snapshot](ec2.WithCloudFormationCreation(ctx, cfnEC2VolumeDeletionSnapshot, identity), h.commands, "ec2", "CreateSnapshot", in)
		if e != nil {
			return false, e
		}
		id = cfnComputeValue(out.SnapshotId)
		if id == "" {
			return false, fmt.Errorf("CreateSnapshot returned no snapshot identity")
		}
	} else if err != nil {
		return false, err
	}
	snapshots, err := cfnComputeCall[api.DescribeSnapshotsResult](ctx, h.commands, "ec2", "DescribeSnapshots", map[string]any{"SnapshotIds": []string{id}})
	if err != nil {
		return false, err
	}
	if len(snapshots.Snapshots) != 1 || cfnComputeValue(snapshots.Snapshots[0].VolumeId) != r.PhysicalID {
		return false, fmt.Errorf("EBS deletion snapshot %s no longer captures volume %s", id, r.PhysicalID)
	}
	snapshot := snapshots.Snapshots[0]
	switch state := cfnComputeValue(snapshot.State); state {
	case "completed":
		return true, nil
	case "pending":
		return false, nil
	default:
		return false, fmt.Errorf("EBS deletion snapshot entered %s: %s", state, cfnComputeValue(snapshot.StateMessage))
	}
}
