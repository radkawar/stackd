package ec2

import (
	"slices"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// InstanceProfileAssociationRecord is the authoritative EC2 relationship. IAM
// continues to own profile membership, role trust and issued session credentials.
// NextActionAt retains a transition independently of the native guest worker.
// All transitions and the Instance.IamInstanceProfile projection commit together.
type InstanceProfileAssociationRecord struct {
	Key                     ResourceKey
	InstanceID              string
	ProfileARN, ProfileID   string
	State                   api.IamInstanceProfileAssociationState
	Timestamp, NextActionAt time.Time
	Credentials             InstanceCredentialReferences
}

func (v InstanceProfileAssociationRecord) profile() *api.IamInstanceProfile {
	return &api.IamInstanceProfile{Arn: new(api.String(v.ProfileARN)), Id: new(api.String(v.ProfileID))}
}

func (v InstanceProfileAssociationRecord) wire() api.IamInstanceProfileAssociation {
	return api.IamInstanceProfileAssociation{AssociationId: new(api.String(v.Key.ID)), InstanceId: new(api.String(v.InstanceID)), IamInstanceProfile: v.profile(), State: new(v.State)}
}

func cloneInstanceProfileAssociation(v InstanceProfileAssociationRecord) InstanceProfileAssociationRecord {
	return v
}

func (r memoryReader) InstanceProfileAssociation(k ResourceKey) (InstanceProfileAssociationRecord, error) {
	return getRecord(r.tx, r.s.profileAssociations, k, cloneInstanceProfileAssociation)
}
func (r memoryReader) InstanceProfileAssociations(scope Scope) ([]InstanceProfileAssociationRecord, error) {
	return listRecords(r.tx, r.s.profileAssociations, scope, cloneInstanceProfileAssociation)
}
func (w memoryWriter) PutInstanceProfileAssociation(v InstanceProfileAssociationRecord) error {
	return putRecord(w.tx, w.s.profileAssociations, v.Key, v, cloneInstanceProfileAssociation)
}
func (w memoryWriter) DeleteInstanceProfileAssociation(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.profileAssociations, k)
}
func (r memoryReader) PendingInstanceProfileAssociations(deadline time.Time) ([]InstanceProfileAssociationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []InstanceProfileAssociationRecord{}
	for _, record := range r.s.profileAssociations {
		if !record.NextActionAt.IsZero() && !record.NextActionAt.After(deadline) {
			out = append(out, record)
		}
	}
	slices.SortFunc(out, func(a, b InstanceProfileAssociationRecord) int { return compareInstanceKeys(a.Key, b.Key) })
	return out, nil
}
func (r memoryReader) NextInstanceProfileAssociationDeadline() (time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, false, err
	}
	var next time.Time
	for _, record := range r.s.profileAssociations {
		if !record.NextActionAt.IsZero() && (next.IsZero() || record.NextActionAt.Before(next)) {
			next = record.NextActionAt
		}
	}
	return next, !next.IsZero(), nil
}

func captureMetadataBlockDevices(record *InstanceRecord) {
	record.MetadataBlockDevices = make([]string, 0, len(record.Data.BlockDeviceMappings))
	for _, mapping := range record.Data.BlockDeviceMappings {
		if mapping.Ebs != nil && str(mapping.Ebs.Status) != "detaching" {
			record.MetadataBlockDevices = append(record.MetadataBlockDevices, str(mapping.DeviceName))
		}
	}
}
