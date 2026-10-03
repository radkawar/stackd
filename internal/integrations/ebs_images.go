package integrations

import (
	"context"

	"stackd/internal/awsctx"
	"stackd/storage/ec2"
)

// EBSImages joins snapshot deletion to the authoritative AMI repository. It does
// not require an EC2 Service construction cycle or copy image references to EBS.
type EBSImages struct {
	Repository ec2.Repository
}

func (a *EBSImages) ImageReferencingSnapshot(ctx context.Context, owner, snapshotID string) (string, error) {
	var imageID string
	err := a.Repository.View(ctx, func(r ec2.Reader) error {
		m := awsctx.FromContext(r.Context())
		var err error
		imageID, err = r.ImageReferencingSnapshot(ec2.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, owner, snapshotID)
		return err
	})
	return imageID, err
}
