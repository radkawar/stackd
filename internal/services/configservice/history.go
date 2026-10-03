package configservice

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	api "stackd/internal/awsapi/configservice"
	"strings"
)

func registerHistory(s *Service) {
	register(s, "GetResourceConfigHistory", s.resourceHistory)
	register(s, "ListDiscoveredResources", s.listDiscovered)
	register(s, "BatchGetResourceConfig", s.batchGet)
	register(s, "GetDiscoveredResourceCounts", s.resourceCounts)
}

type pageCursor struct {
	Scope   Scope
	Query   string
	Offset  int
	Horizon int64
}

func pageStart(scope Scope, query, token string, rows []Item) (pageCursor, error) {
	cursor := pageCursor{Scope: scope, Query: query}
	for _, row := range rows {
		cursor.Horizon = max(cursor.Horizon, row.Sequence)
	}
	if token == "" {
		return cursor, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return cursor, failure("InvalidNextTokenException", "Invalid pagination token.")
	}
	if err := json.Unmarshal(raw, &cursor); err != nil || cursor.Scope != scope || cursor.Query != query || cursor.Offset < 0 || cursor.Horizon < 0 {
		return cursor, failure("InvalidNextTokenException", "Pagination token does not match this request.")
	}
	return cursor, nil
}
func nextPage(cursor pageCursor, offset, total int) *api.NextToken {
	if offset >= total {
		return nil
	}
	cursor.Offset = offset
	raw, _ := json.Marshal(cursor)
	return new(api.NextToken(base64.RawURLEncoding.EncodeToString(raw)))
}
func pageLimit(limit *api.Limit, maximum int) (int, error) {
	if limit == nil || *limit == 0 {
		return maximum, nil
	}
	if *limit < 0 || int(*limit) > maximum {
		return 0, failure("InvalidLimitException", fmt.Sprintf("Limit must be between 1 and %d.", maximum))
	}
	return int(*limit), nil
}
func (s *Service) resourceHistory(tx Transaction, in *api.GetResourceConfigHistoryInput) (*api.GetResourceConfigHistoryOutput, error) {
	if err := s.authorize(tx.Context(), "GetResourceConfigHistory"); err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.Limit, 100)
	if err != nil {
		return nil, err
	}
	if in.EarlierTime != nil && in.LaterTime != nil && in.EarlierTime.After(*in.LaterTime) {
		return nil, failure("InvalidTimeRangeException", "")
	}
	order := value(in.ChronologicalOrder)
	if order == "" {
		order = "Reverse"
	}
	if order != "Forward" && order != "Reverse" {
		return nil, failure("ValidationException", "Invalid chronological order.")
	}
	rows, err := tx.Items(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	queryBytes, _ := json.Marshal([]any{"history", value(in.ResourceType), value(in.ResourceId), order, in.EarlierTime, in.LaterTime})
	cursor, err := pageStart(scopeFor(tx.Context()), string(queryBytes), value(in.NextToken), rows)
	if err != nil {
		return nil, err
	}
	filtered := make([]Item, 0)
	exists := false
	for _, row := range rows {
		if row.ResourceType != value(in.ResourceType) || row.ResourceID != value(in.ResourceId) || row.Sequence > cursor.Horizon {
			continue
		}
		exists = true
		if in.EarlierTime != nil && in.LaterTime != nil && in.EarlierTime.Equal(*in.LaterTime) {
			continue
		}
		if in.EarlierTime != nil && row.CaptureTime.Before(*in.EarlierTime) || in.LaterTime != nil && row.CaptureTime.After(*in.LaterTime) {
			continue
		}
		filtered = append(filtered, row)
	}
	if !exists {
		return nil, failure("ResourceNotDiscoveredException", "The specified resource has not been discovered.")
	}
	slices.SortFunc(filtered, func(a, b Item) int {
		v := a.CaptureTime.Compare(b.CaptureTime)
		if v == 0 {
			if a.Sequence < b.Sequence {
				v = -1
			} else if a.Sequence > b.Sequence {
				v = 1
			}
		}
		if order == "Reverse" {
			return -v
		}
		return v
	})
	if cursor.Offset > len(filtered) {
		return nil, failure("InvalidNextTokenException", "Pagination token is out of bounds.")
	}
	end := min(cursor.Offset+limit, len(filtered))
	out := &api.GetResourceConfigHistoryOutput{ConfigurationItems: api.ConfigurationItemList{}, NextToken: nextPage(cursor, end, len(filtered))}
	for _, row := range filtered[cursor.Offset:end] {
		out.ConfigurationItems = append(out.ConfigurationItems, row.ConfigurationItem())
	}
	return out, nil
}
func (s *Service) listDiscovered(tx Transaction, in *api.ListDiscoveredResourcesInput) (*api.ListDiscoveredResourcesOutput, error) {
	if err := s.authorize(tx.Context(), "ListDiscoveredResources"); err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.Limit, 100)
	if err != nil {
		return nil, err
	}
	if len(in.ResourceIds) > 0 && in.ResourceName != nil {
		return nil, failure("InvalidParameterValueException", "ResourceIds and ResourceName cannot be combined.")
	}
	rows, err := tx.Items(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	queryBytes, _ := json.Marshal([]any{"discover", in.ResourceType, in.ResourceIds, in.ResourceName, boolean(in.IncludeDeletedResources)})
	cursor, err := pageStart(scopeFor(tx.Context()), string(queryBytes), value(in.NextToken), rows)
	if err != nil {
		return nil, err
	}
	bounded := rows[:0]
	for _, row := range rows {
		if row.Sequence <= cursor.Horizon {
			bounded = append(bounded, row)
		}
	}
	latest := latestItems(bounded)
	filtered := make([]Item, 0)
	for _, row := range latest {
		if row.ResourceType != value(in.ResourceType) || row.Status == "ResourceDeleted" && !boolean(in.IncludeDeletedResources) || len(in.ResourceIds) > 0 && !slices.Contains(in.ResourceIds, api.ResourceId(row.ResourceID)) || in.ResourceName != nil && row.ResourceName != value(in.ResourceName) {
			continue
		}
		filtered = append(filtered, row)
	}
	slices.SortFunc(filtered, func(a, b Item) int { return strings.Compare(a.ResourceID, b.ResourceID) })
	if cursor.Offset > len(filtered) {
		return nil, failure("InvalidNextTokenException", "Pagination token is out of bounds.")
	}
	end := min(cursor.Offset+limit, len(filtered))
	out := &api.ListDiscoveredResourcesOutput{ResourceIdentifiers: api.ResourceIdentifierList{}, NextToken: nextPage(cursor, end, len(filtered))}
	for _, row := range filtered[cursor.Offset:end] {
		id := api.ResourceIdentifier{ResourceType: new(api.ResourceType(row.ResourceType)), ResourceId: new(api.ResourceId(row.ResourceID))}
		if row.ResourceName != "" {
			id.ResourceName = new(api.ResourceName(row.ResourceName))
		}
		if row.Status == "ResourceDeleted" {
			id.ResourceDeletionTime = &row.CaptureTime
		}
		out.ResourceIdentifiers = append(out.ResourceIdentifiers, id)
	}
	return out, nil
}
func baseItem(item Item) api.BaseConfigurationItem {
	full := item.ConfigurationItem()
	return api.BaseConfigurationItem{AccountId: full.AccountId, Arn: full.Arn, AvailabilityZone: full.AvailabilityZone, AwsRegion: full.AwsRegion, Configuration: full.Configuration, ConfigurationItemCaptureTime: full.ConfigurationItemCaptureTime, ConfigurationItemStatus: full.ConfigurationItemStatus, ConfigurationStateId: full.ConfigurationStateId, ResourceCreationTime: full.ResourceCreationTime, ResourceId: full.ResourceId, ResourceName: full.ResourceName, ResourceType: full.ResourceType, SupplementaryConfiguration: full.SupplementaryConfiguration, Version: full.Version}
}
func (s *Service) batchGet(tx Transaction, in *api.BatchGetResourceConfigInput) (*api.BatchGetResourceConfigOutput, error) {
	if err := s.authorize(tx.Context(), "BatchGetResourceConfig"); err != nil {
		return nil, err
	}
	if len(in.ResourceKeys) == 0 || len(in.ResourceKeys) > 100 {
		return nil, failure("ValidationException", "ResourceKeys must contain 1 to 100 keys.")
	}
	rows, err := tx.Items(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	latest := latestItems(rows)
	out := &api.BatchGetResourceConfigOutput{BaseConfigurationItems: api.BaseConfigurationItems{}, UnprocessedResourceKeys: api.ResourceKeys{}}
	seen := map[string]bool{}
	for _, key := range in.ResourceKeys {
		k := value(key.ResourceType) + "\x00" + value(key.ResourceId)
		if seen[k] {
			continue
		}
		seen[k] = true
		if item, ok := latest[k]; ok && item.Status != "ResourceDeleted" {
			out.BaseConfigurationItems = append(out.BaseConfigurationItems, baseItem(item))
		}
	}
	return out, nil
}
func (s *Service) resourceCounts(tx Transaction, in *api.GetDiscoveredResourceCountsInput) (*api.GetDiscoveredResourceCountsOutput, error) {
	if err := s.authorize(tx.Context(), "GetDiscoveredResourceCounts"); err != nil {
		return nil, err
	}
	limit, err := pageLimit(in.Limit, 100)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Items(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	queryBytes, _ := json.Marshal([]any{"counts", in.ResourceTypes})
	cursor, err := pageStart(scopeFor(tx.Context()), string(queryBytes), value(in.NextToken), rows)
	if err != nil {
		return nil, err
	}
	bounded := rows[:0]
	for _, row := range rows {
		if row.Sequence <= cursor.Horizon {
			bounded = append(bounded, row)
		}
	}
	counts := map[string]int64{}
	var total int64
	for _, row := range latestItems(bounded) {
		if row.Status == "ResourceDeleted" || len(in.ResourceTypes) > 0 && !slices.Contains(in.ResourceTypes, api.StringWithCharLimit256(row.ResourceType)) {
			continue
		}
		counts[row.ResourceType]++
		total++
	}
	keys := slices.Sorted(maps.Keys(counts))
	if cursor.Offset > len(keys) {
		return nil, failure("InvalidNextTokenException", "Pagination token is out of bounds.")
	}
	end := min(cursor.Offset+limit, len(keys))
	out := &api.GetDiscoveredResourceCountsOutput{TotalDiscoveredResources: new(api.Long(total)), ResourceCounts: api.ResourceCounts{}, NextToken: nextPage(cursor, end, len(keys))}
	for _, kind := range keys[cursor.Offset:end] {
		out.ResourceCounts = append(out.ResourceCounts, api.ResourceCount{ResourceType: new(api.ResourceType(kind)), Count: new(api.Long(counts[kind]))})
	}
	return out, nil
}
