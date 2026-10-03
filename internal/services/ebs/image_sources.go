package ebs

import (
	"context"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ec2"
)

var _ ec2.ImageSnapshots = (*Service)(nil)

// ImageReferences is the snapshot owner's dependency query into the AMI catalog.
// Implementations join the caller transaction; EBS never mirrors image mappings.
type ImageReferences interface {
	ImageReferencingSnapshot(context.Context, string, string) (string, error)
}

// ResolveImageSnapshots supplies visible metadata to image admission without
// granting or requiring DescribeSnapshots. RegisterImage owns its action-specific
// snapshot IAM and ownership checks. Immutable block payloads are not read here.
func (s *Service) ResolveImageSnapshots(ctx context.Context, ids []string) (api.SnapshotList, error) {
	out := make(api.SnapshotList, 0, len(ids))
	err := s.repository.View(ctx, func(r Reader) error {
		account := scopeFor(r.Context()).AccountID
		for _, id := range ids {
			v, err := s.ec2Snapshot(r, id)
			if err != nil {
				return err
			}
			visible, err := s.ec2Visible(r, v)
			if err != nil {
				return err
			}
			if !visible {
				return ec2SnapshotMissing(id)
			}
			if v.Key.AccountID != account {
				v.Tags, err = r.SharedTags(SharedTagsKey{Snapshot: v.Key, AccountID: account})
				if err != nil {
					return err
				}
			}
			out = append(out, snapshotProjection(&v))
		}
		return nil
	})
	return out, err
}
