package integrations

import (
	"context"

	"stackd/storage/ec2"
)

// EBSInstances reads the instance-owned attachment relationship in the caller's
// shared transaction. Stop preserves mappings; only observed detach removes them.
type EBSInstances struct{ Repository ec2.Repository }

func (a EBSInstances) InstanceVolumeAttachments(ctx context.Context, key ec2.ResourceKey) ([]ec2.InstanceVolumeAttachmentRecord, error) {
	var out []ec2.InstanceVolumeAttachmentRecord
	err := a.Repository.View(ctx, func(r ec2.Reader) error {
		var err error
		out, err = r.InstanceVolumeAttachments(key)
		return err
	})
	return out, err
}
