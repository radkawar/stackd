package ec2

import (
	"cmp"
	"slices"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// InstanceVolumeAttachmentRecord projects the instance-owned relationship; EBS
// queries it for in-use checks without maintaining a second attachment ledger.
type InstanceVolumeAttachmentRecord struct {
	InstanceKey ResourceKey
	Mapping     api.InstanceBlockDeviceMapping
}

func (r memoryReader) Instance(k ResourceKey) (InstanceRecord, error) {
	return getRecord(r.tx, r.s.instances, k, cloneInstance)
}
func (r memoryReader) Instances(scope Scope) ([]InstanceRecord, error) {
	return listRecords(r.tx, r.s.instances, scope, cloneInstance)
}
func (w memoryWriter) PutInstance(v InstanceRecord) error {
	return putRecord(w.tx, w.s.instances, v.Key, v, cloneInstance)
}
func (r memoryReader) Reservation(k ResourceKey) (ReservationRecord, error) {
	return getRecord(r.tx, r.s.reservations, k, cloneReservation)
}
func (w memoryWriter) PutReservation(v ReservationRecord) error {
	return putRecord(w.tx, w.s.reservations, v.Key, v, cloneReservation)
}
func (r memoryReader) InstanceReservationsByToken(scope Scope, token string) ([]ReservationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ReservationRecord{}
	for k, v := range r.s.reservations {
		if k.Scope == scope && v.ClientToken == token {
			out = append(out, cloneReservation(v))
		}
	}
	slices.SortFunc(out, func(a, b ReservationRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return out, nil
}
func (r memoryReader) PreparedInstances() ([]InstanceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []InstanceRecord{}
	for _, record := range r.s.instances {
		if record.RuntimePrepared {
			out = append(out, cloneInstance(record))
		}
	}
	slices.SortFunc(out, func(a, b InstanceRecord) int { return compareInstanceKeys(a.Key, b.Key) })
	return out, nil
}

func (r memoryReader) PendingInstances(deadline time.Time) ([]InstanceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []InstanceRecord{}
	for _, v := range r.s.instances {
		if !v.NextActionAt.IsZero() && !v.NextActionAt.After(deadline) {
			out = append(out, cloneInstance(v))
		}
	}
	slices.SortFunc(out, func(a, b InstanceRecord) int {
		if n := a.NextActionAt.Compare(b.NextActionAt); n != 0 {
			return n
		}
		return compareInstanceKeys(a.Key, b.Key)
	})
	return out, nil
}
func (r memoryReader) NextInstanceDeadline() (time.Time, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return time.Time{}, false, err
	}
	var next time.Time
	for _, v := range r.s.instances {
		if !v.NextActionAt.IsZero() && (next.IsZero() || v.NextActionAt.Before(next)) {
			next = v.NextActionAt
		}
	}
	return next, !next.IsZero(), nil
}
func (r memoryReader) InstanceVolumeAttachments(volume ResourceKey) ([]InstanceVolumeAttachmentRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []InstanceVolumeAttachmentRecord{}
	for key, instance := range r.s.instances {
		if key.Scope != volume.Scope {
			continue
		}
		for _, mapping := range instance.Data.BlockDeviceMappings {
			if mapping.Ebs != nil && str(mapping.Ebs.VolumeId) == volume.ID && str(mapping.Ebs.Status) != "detached" {
				out = append(out, InstanceVolumeAttachmentRecord{InstanceKey: key, Mapping: api.CloneInstanceBlockDeviceMapping(mapping)})
			}
		}
	}
	slices.SortFunc(out, func(a, b InstanceVolumeAttachmentRecord) int {
		if n := compareInstanceKeys(a.InstanceKey, b.InstanceKey); n != 0 {
			return n
		}
		return cmp.Compare(str(a.Mapping.DeviceName), str(b.Mapping.DeviceName))
	})
	return out, nil
}
func compareInstanceKeys(a, b ResourceKey) int {
	if n := cmp.Compare(a.Scope.Partition, b.Scope.Partition); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Scope.AccountID, b.Scope.AccountID); n != 0 {
		return n
	}
	if n := cmp.Compare(a.Scope.Region, b.Scope.Region); n != 0 {
		return n
	}
	return cmp.Compare(a.ID, b.ID)
}

type instanceCreditDefaultKey struct {
	Scope  Scope
	Family string
}

func cloneInstanceCreditDefault(v InstanceCreditDefaultRecord) InstanceCreditDefaultRecord {
	v.Changes = slices.Clone(v.Changes)
	return v
}
func (r memoryReader) InstanceCreditDefault(scope Scope, family string) (InstanceCreditDefaultRecord, error) {
	return getRecord(r.tx, r.s.creditDefaults, instanceCreditDefaultKey{scope, family}, cloneInstanceCreditDefault)
}
func (w memoryWriter) PutInstanceCreditDefault(v InstanceCreditDefaultRecord) error {
	return putRecord(w.tx, w.s.creditDefaults, instanceCreditDefaultKey{v.Scope, v.Family}, v, cloneInstanceCreditDefault)
}
func cloneInstanceCreditLaunches(v InstanceCreditLaunchRecord) InstanceCreditLaunchRecord {
	v.Starts = slices.Clone(v.Starts)
	return v
}
func (r memoryReader) InstanceCreditLaunches(scope Scope) (InstanceCreditLaunchRecord, error) {
	return getRecord(r.tx, r.s.creditLaunches, scope, cloneInstanceCreditLaunches)
}
func (w memoryWriter) PutInstanceCreditLaunches(v InstanceCreditLaunchRecord) error {
	return putRecord(w.tx, w.s.creditLaunches, v.Scope, v, cloneInstanceCreditLaunches)
}
func cloneInstanceCreditModification(v InstanceCreditModificationRecord) InstanceCreditModificationRecord {
	v.Specifications = slices.Clone(v.Specifications)
	v.Result = api.CloneModifyInstanceCreditSpecificationResult(v.Result)
	return v
}
func (r memoryReader) InstanceCreditModification(k InstanceCreditModificationKey) (InstanceCreditModificationRecord, error) {
	return getRecord(r.tx, r.s.creditModifications, k, cloneInstanceCreditModification)
}
func (w memoryWriter) PutInstanceCreditModification(v InstanceCreditModificationRecord) error {
	return putRecord(w.tx, w.s.creditModifications, v.Key, v, cloneInstanceCreditModification)
}
