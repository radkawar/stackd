package ec2

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// ImageSnapshots resolves visible snapshot metadata in the request's partition,
// account and region, joining its transaction. This is service admission, not a
// DescribeSnapshots API call: implementations must not require that IAM action.
// EBS remains the sole snapshot and disk owner.
type ImageSnapshots interface {
	ResolveImageSnapshots(context.Context, []string) (api.SnapshotList, error)
}

// ImageRecord is the sole AMI catalog record consumed by instance launch and
// CreateImage. SnapshotOwners contains reference identity only, keyed by the
// snapshot IDs in Data.BlockDeviceMappings; it is not a snapshot metadata cache.
// CreateImage may retain pending Data.State until its owned snapshots complete.
// PutImage publishes both image metadata and its snapshot references atomically.
type ImageRecord struct {
	Key               ResourceKey
	Data              api.Image
	LaunchPermissions api.LaunchPermissionList
	SnapshotOwners    map[string]string
	Create            *ImageCreation
}

func cloneImage(v ImageRecord) ImageRecord {
	v.Data = api.CloneImage(v.Data)
	v.LaunchPermissions = api.CloneLaunchPermissionList(v.LaunchPermissions)
	v.SnapshotOwners = maps.Clone(v.SnapshotOwners)
	v.Create = copyPointer(v.Create)
	return v
}

func (r memoryReader) Image(k ResourceKey) (ImageRecord, error) {
	return getRecord(r.tx, r.s.images, k, cloneImage)
}

func (r memoryReader) Images(scope Scope) ([]ImageRecord, error) {
	return listRecords(r.tx, r.s.images, scope, cloneImage)
}

func (r memoryReader) RegionalImages(scope Scope) ([]ImageRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ImageRecord{}
	for k, image := range r.s.images {
		if k.Scope.Partition == scope.Partition && k.Scope.Region == scope.Region {
			out = append(out, cloneImage(image))
		}
	}
	slices.SortFunc(out, func(a, b ImageRecord) int { return strings.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}

func (w memoryWriter) PutImage(v ImageRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for k, image := range w.s.images {
		if k != v.Key && k.Scope == v.Key.Scope && str(image.Data.State) != "deregistered" && str(v.Data.State) != "deregistered" && str(image.Data.Name) == str(v.Data.Name) {
			return duplicateImageName(str(v.Data.Name))
		}
	}
	return putRecord(w.tx, w.s.images, v.Key, v, cloneImage)
}

func (w memoryWriter) DeleteImage(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.images, k)
}

// ImageReferencingSnapshot returns one registered image using this snapshot,
// including data mappings. The reference identity remains owned by the AMI.
func (r memoryReader) ImageReferencingSnapshot(scope Scope, owner, snapshotID string) (string, error) {
	if err := r.tx.Check(false); err != nil {
		return "", err
	}
	found := ""
	for k, image := range r.s.images {
		if k.Scope.Partition != scope.Partition || k.Scope.Region != scope.Region || str(image.Data.State) == "deregistered" || image.SnapshotOwners[snapshotID] != owner {
			continue
		}
		for _, mapping := range image.Data.BlockDeviceMappings {
			if mapping.Ebs != nil && str(mapping.Ebs.SnapshotId) == snapshotID {
				if found == "" || k.ID < found {
					found = k.ID
				}
				break
			}
		}
	}
	return found, nil
}

func (r memoryReader) RegionalImage(scope Scope, id string) (ImageRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ImageRecord{}, err
	}
	for k, image := range r.s.images {
		if k.Scope.Partition == scope.Partition && k.Scope.Region == scope.Region && k.ID == id {
			return cloneImage(image), nil
		}
	}
	return ImageRecord{}, ErrNotFound
}

func (r memoryReader) NextImageDeadline() (time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, false, err
	}
	var next time.Time
	for _, image := range r.s.images {
		if image.Create == nil {
			continue
		}
		due := image.Create.NextActionAt
		if !due.IsZero() && (next.IsZero() || due.Before(next)) {
			next = due
		}
	}
	return next, !next.IsZero(), nil
}

func (r memoryReader) PendingImages(deadline time.Time) ([]ImageRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ImageRecord{}
	for _, image := range r.s.images {
		if image.Create != nil && !image.Create.NextActionAt.IsZero() && !image.Create.NextActionAt.After(deadline) {
			out = append(out, cloneImage(image))
		}
	}
	slices.SortFunc(out, func(a, b ImageRecord) int {
		if n := a.Create.NextActionAt.Compare(b.Create.NextActionAt); n != 0 {
			return n
		}
		return compareInstanceKeys(a.Key, b.Key)
	})
	return out, nil
}
