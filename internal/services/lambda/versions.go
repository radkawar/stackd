package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) registerVersions() {
	register(s, "PublishVersion", s.publishVersion)
	register(s, "ListVersionsByFunction", s.listVersionsByFunction)
}

func publishToError() *awswire.Error {
	return failure("InvalidParameterValueException", "Publishing to LATEST_PUBLISHED is only supported for Lambda Managed Instances.", 400)
}

// publishSnapshot runs in the deployment transaction. DeploymentRevision is the
// publication eligibility identity, including successful same-value updates.
func publishSnapshot(tx Transaction, latest FunctionRecord, description *api.Description) (FunctionRecord, bool, error) {
	last, err := tx.LastAllocatedVersion(latest.Key)
	if err != nil {
		return FunctionRecord{}, false, err
	}
	if last != 0 {
		published, err := tx.FunctionVersion(FunctionVersionKey{FunctionKey: latest.Key, Version: last})
		if err == nil && published.DeploymentRevision == latest.DeploymentRevision {
			return published, false, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return FunctionRecord{}, false, err
		}
	}
	if err := validateCapacityPublication(tx, latest, 0); err != nil {
		return FunctionRecord{}, false, err
	}
	published := latest
	published.Version, err = tx.AllocateFunctionVersion(latest.Key)
	if err != nil {
		return FunctionRecord{}, false, err
	}
	published.Revision = uuid.NewString()
	published.Tags = nil
	if description != nil {
		published.Description = string(*description)
	}
	if latest.State == "Pending" || latest.UpdateStatus == "InProgress" || latest.Capacity != nil {
		published.State, published.StateReason, published.StateReasonCode = "Pending", "The function is being created.", "Creating"
		published.UpdateStatus, published.UpdateReason = "", ""
	}
	if err := tx.PutFunctionVersion(published); err != nil {
		return FunctionRecord{}, false, err
	}
	mode, err := tx.RuntimeManagement(FunctionVersionKey{FunctionKey: latest.Key})
	if err != nil {
		return FunctionRecord{}, false, err
	}
	if err := tx.PutRuntimeManagement(FunctionVersionKey{FunctionKey: published.Key, Version: published.Version}, mode); err != nil {
		return FunctionRecord{}, false, err
	}
	return published, true, nil
}

func (s *Service) publishVersion(ctx context.Context, in *api.PublishVersionInput) (*api.PublishVersionOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	if ref.Qualifier != "" && ref.Qualifier != "$LATEST" {
		return nil, failure("InvalidParameterValueException", "Published versions are immutable; publish from $LATEST.", 400)
	}
	var published FunctionRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		latest, err := loadFunction(tx, ref)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "PublishVersion", ref, latest, nil); wire != nil {
			return wire
		}
		owner, wire := versionOwnerFor(tx.Context())
		if wire != nil {
			return wire
		}
		if owner != (VersionOwner{}) {
			if in.PublishTo != nil {
				return failure("InvalidParameterValueException", "Owned publications require an immutable numbered version.", 400)
			}
			published, err = tx.OwnedFunctionVersion(ref.FunctionKey, owner)
			if err == nil {
				return s.recordCall(tx.Context(), "PublishVersion", in, configuration(published), nil)
			}
			if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if latest.State == "Pending" || latest.UpdateStatus == "InProgress" {
			return failure("ResourceConflictException", "A function deployment is already in progress.", 409)
		}
		if in.RevisionId != nil && value(in.RevisionId) != latest.Revision {
			return failure("PreconditionFailedException", "The RevisionId does not match the current function revision.", 412)
		}
		if in.CodeSha256 != nil && value(in.CodeSha256) != latest.CodeSHA256 {
			return failure("InvalidParameterValueException", "The CodeSha256 does not match the current function code.", 400)
		}
		var created bool
		if in.PublishTo != nil {
			published, created, err = publishCapacitySnapshot(tx, latest, in.Description)
		} else {
			published, created, err = publishSnapshot(tx, latest, in.Description)
		}
		if err != nil {
			return err
		}
		if owner != (VersionOwner{}) {
			if !created {
				return failure("ResourceConflictException", fmt.Sprintf("A version for this Lambda function exists ( %d ). Modify the function to create a new version.", published.Version), 409)
			}
			if err := tx.PutFunctionVersionOwner(FunctionVersionKey{FunctionKey: published.Key, Version: published.Version}, owner); err != nil {
				return err
			}
		}
		if created {
			latest.Revision = uuid.NewString()
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), "PublishVersion", in, configuration(published), nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return configuration(published), nil
}

// Listing omits readiness fields and explicitly qualifies $LATEST when versions
// are requested, unlike the unqualified GetFunction configuration.
func listedConfiguration(record FunctionRecord, qualified bool) api.FunctionConfiguration {
	out := configuration(record)
	if qualified {
		out.FunctionArn = new(api.NameSpacedFunctionArn(record.Key.ARN() + ":" + versionName(record.Version)))
	}
	out.State, out.StateReason, out.StateReasonCode = nil, nil, nil
	out.LastUpdateStatus, out.LastUpdateStatusReason, out.LastUpdateStatusReasonCode = nil, nil, nil
	out.RuntimeVersionConfig = nil
	return *out
}

func versionListPosition(record FunctionRecord) string {
	return fmt.Sprintf("%s:%020d", record.Key.Name, record.Version)
}

func functionPage(records []FunctionRecord, marker string, maxItems *api.MaxListItems, prefix string, qualified bool) (api.FunctionList, *api.String, *awswire.Error) {
	after := ""
	if marker != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(marker)
		if err != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, nil, failure("InvalidParameterValueException", "Invalid pagination marker.", 400)
		}
		after = strings.TrimPrefix(string(decoded), prefix)
	}
	limit := 50
	if maxItems != nil {
		if int(*maxItems) < limit {
			limit = int(*maxItems)
		}
	}
	slices.SortFunc(records, func(a, b FunctionRecord) int {
		if cmp := strings.Compare(a.Key.Name, b.Key.Name); cmp != 0 {
			return cmp
		}
		if a.Version < b.Version {
			return -1
		}
		if a.Version > b.Version {
			return 1
		}
		return 0
	})
	out := api.FunctionList{}
	last := ""
	for _, record := range records {
		position := versionListPosition(record)
		if position <= after {
			continue
		}
		if len(out) == limit {
			return out, new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + last)))), nil
		}
		out = append(out, listedConfiguration(record, qualified))
		last = position
	}
	return out, nil, nil
}

func (s *Service) listVersionsByFunction(ctx context.Context, in *api.ListVersionsByFunctionInput) (*api.ListVersionsByFunctionOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	if ref.Qualifier != "" {
		return nil, failure("InvalidParameterValueException", "ListVersionsByFunction requires an unqualified function name.", 400)
	}
	var records []FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		latest, err := loadFunction(r, ref)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "ListVersionsByFunction", ref, latest, nil); wire != nil {
			return wire
		}
		if pending, err := r.PendingFunction(ref.FunctionKey); err == nil {
			latest = pending
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		records, err = r.FunctionVersions(ref.FunctionKey)
		if err != nil {
			return err
		}
		records = append(records, latest)
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	versions, next, wire := functionPage(records, value(in.Marker), in.MaxItems, ref.ARN()+"/versions/", true)
	if wire != nil {
		return nil, wire
	}
	return &api.ListVersionsByFunctionOutput{Versions: versions, NextMarker: next}, nil
}
