package cloudwatch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func (s *Service) registerDashboards() {
	register(s, "PutDashboard", s.putDashboard)
	register(s, "GetDashboard", s.getDashboard)
	register(s, "ListDashboards", s.listDashboards)
	register(s, "DeleteDashboards", s.deleteDashboards)
}

func dashboardKey(r Reader, name string) DashboardKey {
	scope := scopeFor(r.Context())
	return DashboardKey{Partition: scope.Partition, AccountID: scope.AccountID, Name: name}
}

func admitDashboardName(name, field string, prefix bool) *awswire.Error {
	if name == "" && !prefix {
		return invalid("The parameter " + field + " is required.")
	}
	if len(name) > 255 {
		return invalid("The value for field " + field + " must not exceed 255 characters.")
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || prefix && c == '.' {
			continue
		}
		return invalid("The value for field " + field + " contains invalid characters.")
	}
	return nil
}

func (s *Service) authorizeDashboard(r Reader, action string, key DashboardKey, tags, requested map[string]string, keys []string) *awswire.Error {
	return s.authorizer.Authorize(r.Context(), authorization.Request{
		Action: "cloudwatch:" + action, ResourceARN: key.ARN(), ResourceAccountID: key.AccountID,
		Context: cloudwatchTagConditions(tags, requested, keys),
	})
}

func (s *Service) putDashboard(tx Transaction, in *api.PutDashboardInput) (*api.PutDashboardOutput, *awswire.Error) {
	name := value(in.DashboardName)
	if w := admitDashboardName(name, "DashboardName", false); w != nil {
		return nil, w
	}
	key := dashboardKey(tx, name)
	record, err := tx.Dashboard(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	creating := errors.Is(err, ErrNotFound)
	owner, ownerWire := cloudFormationClaim(tx.Context(), record.CFNOwner, !creating)
	if ownerWire != nil {
		return nil, ownerWire
	}
	record.CFNOwner = owner
	var requested map[string]string
	if creating {
		record.Key = key
		if len(in.Tags) > 50 {
			return nil, invalid("The collection Tags must not have a size greater than 50.")
		}
		var w *awswire.Error
		requested, w = admitTags(in.Tags)
		if w != nil {
			return nil, w
		}
	}
	if w := s.authorizeDashboard(tx, "PutDashboard", key, record.Tags, requested, nil); w != nil {
		return nil, w
	}
	if creating && len(requested) != 0 {
		if w := s.authorizeDashboard(tx, "TagResource", key, nil, requested, nil); w != nil {
			return nil, w
		}
	}
	body, warnings, w := admitDashboardBody(value(in.DashboardBody))
	if w != nil {
		return nil, w
	}
	if creating {
		record.Tags = requested
		record.TaggingInitialized = len(requested) != 0
	}
	record.Body = body
	if err := storeDashboard(tx, record, s.clock.Now()); err != nil {
		return nil, wireError(err)
	}
	return &api.PutDashboardOutput{DashboardValidationMessages: warnings}, nil
}

func (s *Service) getDashboard(tx Transaction, in *api.GetDashboardInput) (*api.GetDashboardOutput, *awswire.Error) {
	name := value(in.DashboardName)
	if w := admitDashboardName(name, "DashboardName", false); w != nil {
		return nil, w
	}
	key := dashboardKey(tx, name)
	record, err := tx.Dashboard(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	if w := s.authorizeDashboard(tx, "GetDashboard", key, record.Tags, nil, nil); w != nil {
		return nil, w
	}
	if errors.Is(err, ErrNotFound) {
		return nil, &awswire.Error{Code: "ResourceNotFound", Message: "Dashboard " + name + " does not exist", StatusCode: 404}
	}
	observeCloudFormation(tx.Context(), "Dashboard", name, record.CFNOwner)
	return &api.GetDashboardOutput{
		DashboardArn: new(api.DashboardArn(key.ARN())), DashboardName: new(api.DashboardName(name)), DashboardBody: new(api.DashboardBody(record.Body)),
	}, nil
}

type dashboardCursor struct {
	Key    DashboardKey
	Prefix string
}

func (s *Service) listDashboards(tx Transaction, in *api.ListDashboardsInput) (*api.ListDashboardsOutput, *awswire.Error) {
	key := dashboardKey(tx, "*")
	if w := s.authorizeDashboard(tx, "ListDashboards", key, nil, nil, nil); w != nil {
		return nil, w
	}
	prefix := value(in.DashboardNamePrefix)
	if w := admitDashboardName(prefix, "DashboardNamePrefix", true); w != nil {
		return nil, w
	}
	query := DashboardQuery{Partition: key.Partition, AccountID: key.AccountID, Prefix: prefix, Limit: 1001}
	if in.NextToken != nil {
		encoded, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		var cursor dashboardCursor
		if err != nil || json.Unmarshal(encoded, &cursor) != nil || cursor.Key.Partition != key.Partition || cursor.Key.AccountID != key.AccountID || cursor.Key.Name == "" || cursor.Prefix != prefix || !strings.HasPrefix(cursor.Key.Name, prefix) {
			return nil, failure("ValidationError", "Invalid NextToken")
		}
		query.After = cursor.Key.Name
	}
	records, err := tx.Dashboards(query)
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.ListDashboardsOutput{DashboardEntries: api.DashboardEntries{}}
	if len(records) > 1000 {
		encoded, _ := json.Marshal(dashboardCursor{Key: records[999].Key, Prefix: prefix})
		out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString(encoded)))
		records = records[:1000]
	}
	for _, record := range records {
		out.DashboardEntries = append(out.DashboardEntries, api.DashboardEntry{
			DashboardArn: new(api.DashboardArn(record.Key.ARN())), DashboardName: new(api.DashboardName(record.Key.Name)),
			LastModified: new(api.LastModified(record.Updated)), Size: new(api.Size(record.Size)),
		})
	}
	return out, nil
}

func (s *Service) deleteDashboards(tx Transaction, in *api.DeleteDashboardsInput) (*api.DeleteDashboardsOutput, *awswire.Error) {
	if len(in.DashboardNames) == 0 {
		return nil, invalid("Field DashboardNames is required and has to contain at least 1 element.")
	}
	// The native limit counts distinct names. Validate and authorize the whole
	// deletion set before removing any member, including absent resources.
	keys := make([]DashboardKey, 0, min(len(in.DashboardNames), 100))
	seen := make(map[string]struct{}, cap(keys))
	for i, member := range in.DashboardNames {
		name := string(member)
		if w := admitDashboardName(name, fmt.Sprintf("DashboardNames[%d]", i), false); w != nil {
			return nil, w
		}
		if _, exists := seen[name]; exists {
			continue
		}
		if len(keys) == 100 {
			return nil, invalid("Field DashboardNames can contain up to 100 elements.")
		}
		seen[name] = struct{}{}
		keys = append(keys, dashboardKey(tx, name))
	}
	for _, key := range keys {
		record, err := tx.Dashboard(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, wireError(err)
		}
		if err == nil {
			if w := cloudFormationOwned(tx.Context(), record.CFNOwner); w != nil {
				return nil, w
			}
		}
		if w := s.authorizeDashboard(tx, "DeleteDashboards", key, record.Tags, nil, nil); w != nil {
			return nil, w
		}
	}
	for _, key := range keys {
		if err := tx.DeleteDashboard(key); err != nil {
			return nil, wireError(err)
		}
	}
	return &api.DeleteDashboardsOutput{}, nil
}

func (s *Service) dashboardTagTarget(tx Transaction, arn, action string, requested map[string]string, keys []string) (*DashboardRecord, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "cloudwatch" || !strings.HasPrefix(parts[5], "dashboard/") {
		return nil, invalid("ResourceARN must be a dashboard ARN.")
	}
	name := strings.TrimPrefix(parts[5], "dashboard/")
	if w := admitDashboardName(name, "ResourceARN", false); w != nil {
		return nil, w
	}
	scope := scopeFor(tx.Context())
	if parts[1] != scope.Partition {
		return nil, failure("ResourceNotFoundException", "The specified resource does not exist.")
	}
	if parts[4] != scope.AccountID {
		return nil, failure("InvalidClientTokenId", "No account found for the given parameters")
	}
	if parts[3] != "" && parts[3] != scope.Region {
		return nil, failure("ResourceNotFoundException", "Resource is not reachable in this region ('"+scope.Region+"')")
	}
	if parts[3] != "" {
		return nil, invalid("ARN is invalid.")
	}
	key := dashboardKey(tx, name)
	record, err := tx.Dashboard(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, wireError(err)
	}
	if w := s.authorizeDashboard(tx, action, key, record.Tags, requested, keys); w != nil {
		return nil, w
	}
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFoundException", "The specified resource does not exist.")
	}
	if w := cloudFormationOwned(tx.Context(), record.CFNOwner); w != nil {
		return nil, w
	}
	return &record, nil
}
