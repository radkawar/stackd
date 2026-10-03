package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
)

// SnapshotControl is the EC2 consumer boundary to the shared snapshot owner.
// Controls enforce EC2 IAM authority; EC2's dispatch records their API outcomes.
// Tag accessors join the caller's transaction; EC2 validates and authorizes tags
// before SetSnapshotTags. They must not maintain a second metadata catalog.
type SnapshotControl interface {
	DescribeSnapshots(context.Context, *api.DescribeSnapshotsRequest) (*api.DescribeSnapshotsResult, error)
	CopySnapshot(context.Context, *api.CopySnapshotRequest) (*api.CopySnapshotResult, error)
	DeleteSnapshot(context.Context, *api.DeleteSnapshotRequest) (*api.Unit, error)
	DescribeSnapshotAttribute(context.Context, *api.DescribeSnapshotAttributeRequest) (*api.DescribeSnapshotAttributeResult, error)
	ModifySnapshotAttribute(context.Context, *api.ModifySnapshotAttributeRequest) (*api.Unit, error)
	ResetSnapshotAttribute(context.Context, *api.ResetSnapshotAttributeRequest) (*api.Unit, error)
	GetSnapshotBlockPublicAccessState(context.Context, *api.GetSnapshotBlockPublicAccessStateRequest) (*api.GetSnapshotBlockPublicAccessStateResult, error)
	EnableSnapshotBlockPublicAccess(context.Context, *api.EnableSnapshotBlockPublicAccessRequest) (*api.EnableSnapshotBlockPublicAccessResult, error)
	DisableSnapshotBlockPublicAccess(context.Context, *api.DisableSnapshotBlockPublicAccessRequest) (*api.DisableSnapshotBlockPublicAccessResult, error)
	GetEbsEncryptionByDefault(context.Context, *api.GetEbsEncryptionByDefaultRequest) (*api.GetEbsEncryptionByDefaultResult, error)
	EnableEbsEncryptionByDefault(context.Context, *api.EnableEbsEncryptionByDefaultRequest) (*api.EnableEbsEncryptionByDefaultResult, error)
	DisableEbsEncryptionByDefault(context.Context, *api.DisableEbsEncryptionByDefaultRequest) (*api.DisableEbsEncryptionByDefaultResult, error)
	GetEbsDefaultKmsKeyId(context.Context, *api.GetEbsDefaultKmsKeyIdRequest) (*api.GetEbsDefaultKmsKeyIdResult, error)
	ModifyEbsDefaultKmsKeyId(context.Context, *api.ModifyEbsDefaultKmsKeyIdRequest) (*api.ModifyEbsDefaultKmsKeyIdResult, error)
	ResetEbsDefaultKmsKeyId(context.Context, *api.ResetEbsDefaultKmsKeyIdRequest) (*api.ResetEbsDefaultKmsKeyIdResult, error)
	SnapshotTags(context.Context, string, string) (api.TagList, authorization.Request, error)
	SetSnapshotTags(context.Context, string, api.TagList) error
	ListSnapshotTags(context.Context) (api.TagDescriptionList, error)
}

func registerSnapshots(s *Service) {
	if s.snapshots == nil {
		return
	}
	registerOwnedCommand(s, "DescribeSnapshots", s.snapshots.DescribeSnapshots)
	registerOwnedCommand(s, "CopySnapshot", s.snapshots.CopySnapshot)
	registerOwnedCommand(s, "DeleteSnapshot", s.snapshots.DeleteSnapshot)
	registerOwnedCommand(s, "DescribeSnapshotAttribute", s.snapshots.DescribeSnapshotAttribute)
	registerOwnedCommand(s, "ModifySnapshotAttribute", s.snapshots.ModifySnapshotAttribute)
	registerOwnedCommand(s, "ResetSnapshotAttribute", s.snapshots.ResetSnapshotAttribute)
	registerOwnedCommand(s, "GetSnapshotBlockPublicAccessState", s.snapshots.GetSnapshotBlockPublicAccessState)
	registerOwnedCommand(s, "EnableSnapshotBlockPublicAccess", s.snapshots.EnableSnapshotBlockPublicAccess)
	registerOwnedCommand(s, "DisableSnapshotBlockPublicAccess", s.snapshots.DisableSnapshotBlockPublicAccess)
	registerOwnedCommand(s, "GetEbsEncryptionByDefault", s.snapshots.GetEbsEncryptionByDefault)
	registerOwnedCommand(s, "EnableEbsEncryptionByDefault", s.snapshots.EnableEbsEncryptionByDefault)
	registerOwnedCommand(s, "DisableEbsEncryptionByDefault", s.snapshots.DisableEbsEncryptionByDefault)
	registerOwnedCommand(s, "GetEbsDefaultKmsKeyId", s.snapshots.GetEbsDefaultKmsKeyId)
	registerOwnedCommand(s, "ModifyEbsDefaultKmsKeyId", s.snapshots.ModifyEbsDefaultKmsKeyId)
	registerOwnedCommand(s, "ResetEbsDefaultKmsKeyId", s.snapshots.ResetEbsDefaultKmsKeyId)
}
func registerOwnedCommand[I, O any](s *Service, name string, fn func(context.Context, *I) (*O, error)) {
	register(s, name, func(ctx context.Context, _ Transaction, in *I) (*O, error) { return fn(ctx, in) })
}

// SelectSnapshotPage applies EC2's selectors to authoritative owner projections,
// reusing the same wildcard/filter and scoped-cursor rules as other EC2 resources.
// restorable contains the owner's evaluated permission matches for the original
// RestorableByUserIds selectors; those selectors remain part of the cursor digest.
func SelectSnapshotPage(ctx context.Context, in *api.DescribeSnapshotsRequest, rows api.SnapshotList, restorable map[string]bool) (*api.DescribeSnapshotsResult, error) {
	if in.MaxResults != nil && (*in.MaxResults < 5 || *in.MaxResults > 1000) {
		return nil, failure("InvalidParameterValue", "Value for parameter maxResults is invalid. The valid range is 5 to 1000.")
	}
	if len(in.SnapshotIds) > 0 && (in.MaxResults != nil || str(in.NextToken) != "") {
		return nil, failure("InvalidParameterCombination", "The parameter MaxResults cannot be used with the parameter resource IDs.")
	}
	allowed := map[string]bool{}
	for _, name := range strings.Fields("description encrypted owner-alias owner-id progress snapshot-id start-time status storage-tier volume-id volume-size tag-key tag-value") {
		allowed[name] = true
	}
	for _, f := range in.Filters {
		if !allowed[str(f.Name)] && !strings.HasPrefix(str(f.Name), "tag:") {
			return nil, failure("InvalidParameterValue", "The filter '"+str(f.Name)+"' is invalid")
		}
	}
	wanted := map[string]bool{}
	for _, id := range in.SnapshotIds {
		wanted[string(id)] = true
		found := false
		for _, v := range rows {
			if str(v.SnapshotId) == string(id) {
				found = true
				break
			}
		}
		if !found {
			return nil, failure("InvalidSnapshot.NotFound", "The snapshot '"+string(id)+"' does not exist.")
		}
	}
	selection, _ := json.Marshal(struct {
		Filters    api.FilterList
		Owners     api.OwnerStringList
		Restorable api.RestorableByStringList
	}{in.Filters, in.OwnerIds, in.RestorableByUserIds})
	digest := fmt.Sprintf("%x", sha256.Sum256(selection))
	cursor := pageToken{Scope: scopeFor(ctx), Operation: "DescribeSnapshots", Selection: digest}
	if str(in.NextToken) != "" {
		body, err := base64.RawURLEncoding.DecodeString(str(in.NextToken))
		var prior pageToken
		if err != nil || json.Unmarshal(body, &prior) != nil || prior.Scope != cursor.Scope || prior.Operation != cursor.Operation || prior.Selection != digest || prior.After == "" {
			return nil, failure("InvalidParameterValue", "The nextToken is invalid.")
		}
		cursor = prior
	}
	slices.SortFunc(rows, func(a, b api.Snapshot) int { return strings.Compare(str(a.SnapshotId), str(b.SnapshotId)) })
	compiled := compileFilters(in.Filters)
	limit := len(rows) + 1
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	out := &api.DescribeSnapshotsResult{Snapshots: api.SnapshotList{}}
	for _, v := range rows {
		id := str(v.SnapshotId)
		if id <= cursor.After || len(wanted) > 0 && !wanted[id] {
			continue
		}
		ownerMatch := len(in.OwnerIds) == 0
		for _, owner := range in.OwnerIds {
			if string(owner) == str(v.OwnerId) || owner == "self" && str(v.OwnerId) == scopeFor(ctx).AccountID {
				ownerMatch = true
			}
		}
		if !ownerMatch || len(in.RestorableByUserIds) > 0 && !restorable[id] {
			continue
		}
		size := "0"
		if v.VolumeSize != nil {
			size = strconv.FormatInt(int64(*v.VolumeSize), 10)
		}
		started := ""
		if v.StartTime != nil {
			started = v.StartTime.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		item := pageItem{ID: id, Tags: v.Tags, Fields: map[string][]string{"snapshot-id": {id}, "description": {str(v.Description)}, "encrypted": {strconv.FormatBool(boolValue(v.Encrypted))}, "owner-id": {str(v.OwnerId)}, "owner-alias": {str(v.OwnerAlias)}, "progress": {str(v.Progress)}, "status": {str(v.State)}, "storage-tier": {str(v.StorageTier)}, "volume-id": {str(v.VolumeId)}, "volume-size": {size}, "start-time": {started}}}
		if !matchesFilters(item, compiled) {
			continue
		}
		if len(out.Snapshots) == limit {
			cursor.After = str(out.Snapshots[len(out.Snapshots)-1].SnapshotId)
			body, _ := json.Marshal(cursor)
			out.NextToken = new(api.String(base64.RawURLEncoding.EncodeToString(body)))
			break
		}
		out.Snapshots = append(out.Snapshots, v)
	}
	return out, nil
}
