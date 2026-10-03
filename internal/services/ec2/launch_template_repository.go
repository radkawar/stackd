package ec2

import (
	"cmp"
	"slices"
	"time"

	api "stackd/internal/awsapi/ec2"
)

// LaunchTemplateRecord owns the name and mutable default/latest pointers. The
// allocation counter never rewinds when the most recent version is deleted.
type LaunchTemplateRecord struct {
	Key         ResourceKey
	Data        api.LaunchTemplate
	LastVersion int64
}

type LaunchTemplateVersionKey struct {
	Template ResourceKey
	Number   int64
}

type LaunchTemplateVersionRecord struct {
	Key         LaunchTemplateVersionKey
	CreatedAt   time.Time
	CreatedBy   string
	Description *api.VersionDescription
	Data        api.RequestLaunchTemplateData
}

type LaunchTemplateTokenKey struct {
	Scope         Scope
	Action, Token string
}

// Tokens retain equality and identity, not a second copy of template contents.
type LaunchTemplateTokenRecord struct {
	Key                     LaunchTemplateTokenKey
	Fingerprint, TemplateID string
	Version                 int64
}

func cloneLaunchTemplate(v LaunchTemplateRecord) LaunchTemplateRecord {
	v.Data = api.CloneLaunchTemplate(v.Data)
	return v
}
func cloneLaunchTemplateVersion(v LaunchTemplateVersionRecord) LaunchTemplateVersionRecord {
	v.Description = copyPointer(v.Description)
	v.Data = api.CloneRequestLaunchTemplateData(v.Data)
	return v
}
func (r memoryReader) LaunchTemplate(k ResourceKey) (LaunchTemplateRecord, error) {
	return getRecord(r.tx, r.s.launchTemplates, k, cloneLaunchTemplate)
}
func (r memoryReader) LaunchTemplates(scope Scope) ([]LaunchTemplateRecord, error) {
	return listRecords(r.tx, r.s.launchTemplates, scope, cloneLaunchTemplate)
}
func (w memoryWriter) PutLaunchTemplate(v LaunchTemplateRecord) error {
	return putRecord(w.tx, w.s.launchTemplates, v.Key, v, cloneLaunchTemplate)
}
func (w memoryWriter) DeleteLaunchTemplate(k ResourceKey) error {
	if err := deleteRecord(w.tx, w.s.launchTemplates, k); err != nil {
		return err
	}
	for key := range w.s.launchTemplateVersions {
		if key.Template == k {
			delete(w.s.launchTemplateVersions, key)
		}
	}
	return nil
}
func (r memoryReader) LaunchTemplateVersion(k LaunchTemplateVersionKey) (LaunchTemplateVersionRecord, error) {
	return getRecord(r.tx, r.s.launchTemplateVersions, k, cloneLaunchTemplateVersion)
}
func (r memoryReader) LaunchTemplateVersions(k ResourceKey) ([]LaunchTemplateVersionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []LaunchTemplateVersionRecord{}
	for key, v := range r.s.launchTemplateVersions {
		if key.Template == k {
			out = append(out, cloneLaunchTemplateVersion(v))
		}
	}
	slices.SortFunc(out, func(a, b LaunchTemplateVersionRecord) int { return cmp.Compare(b.Key.Number, a.Key.Number) })
	return out, nil
}
func (w memoryWriter) PutLaunchTemplateVersion(v LaunchTemplateVersionRecord) error {
	return putRecord(w.tx, w.s.launchTemplateVersions, v.Key, v, cloneLaunchTemplateVersion)
}
func (w memoryWriter) DeleteLaunchTemplateVersion(k LaunchTemplateVersionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.launchTemplateVersions[k]; !ok {
		return ErrNotFound
	}
	delete(w.s.launchTemplateVersions, k)
	return nil
}
func (r memoryReader) LaunchTemplateToken(k LaunchTemplateTokenKey) (LaunchTemplateTokenRecord, error) {
	return getRecord(r.tx, r.s.launchTemplateTokens, k, func(v LaunchTemplateTokenRecord) LaunchTemplateTokenRecord { return v })
}
func (w memoryWriter) PutLaunchTemplateToken(v LaunchTemplateTokenRecord) error {
	return putRecord(w.tx, w.s.launchTemplateTokens, v.Key, v, func(v LaunchTemplateTokenRecord) LaunchTemplateTokenRecord { return v })
}
