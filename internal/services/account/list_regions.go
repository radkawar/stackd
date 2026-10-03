package account

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	api "stackd/internal/awsapi/account"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// The cursor is only a position in a public catalogue. Every page separately
// authorizes its account; possessing or modifying a token cannot grant access.
type regionCursor struct {
	Partition, AccountID, After string
	Filter                      []api.RegionOptStatus
}

func (s *Service) listRegions(ctx context.Context, in api.ListRegionsInput) (any, error) {
	output := &api.ListRegionsOutput{Regions: []api.Region{}}
	err := s.repository.View(ctx, func(reader Reader) error {
		ctx, instant := reader.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "ListRegions", value(in.AccountId), nil, instant)
		if err != nil {
			return err
		}
		partition := awsctx.FromContext(ctx).Partition
		if partition != "aws" {
			return failure("AccessDeniedException", "Account region management is unavailable in this partition.", 403)
		}
		filter := slices.Clone(in.RegionOptStatusContains)
		values := enumValues("RegionOptStatus")
		for _, status := range filter {
			if !slices.Contains(values, string(status)) {
				encoded, err := json.Marshal(values)
				if err != nil {
					return err
				}
				return failure("ValidationException", fmt.Sprintf("[instance value (%q) not found in enum (possible values: %s)]", status, encoded), 400)
			}
		}
		slices.Sort(filter)
		filter = slices.Compact(filter)
		cursor := regionCursor{Partition: partition, AccountID: target, Filter: filter}
		if in.NextToken != nil {
			data, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
			var supplied regionCursor
			if err != nil || json.Unmarshal(data, &supplied) != nil || supplied.Partition != partition || supplied.AccountID != target || !slices.Equal(supplied.Filter, filter) || supplied.After == "" {
				return validation("NextToken", "NextToken is malformed", "fieldValidationFailed")
			}
			cursor.After = supplied.After
		}
		limit := 20
		if in.MaxResults != nil {
			limit = int(*in.MaxResults)
		}
		for _, region := range awscatalog.CommercialRegions() {
			if region.Name <= cursor.After {
				continue
			}
			status, err := regionStatus(reader, RegionKey{partition, target, region.Name}, instant)
			if err != nil {
				return err
			}
			if len(filter) != 0 && !slices.Contains(filter, api.RegionOptStatus(status)) {
				continue
			}
			if len(output.Regions) == limit {
				cursor.After = value(output.Regions[len(output.Regions)-1].RegionName)
				data, err := json.Marshal(cursor)
				if err != nil {
					return err
				}
				output.NextToken = ptr(api.String(base64.RawURLEncoding.EncodeToString(data)))
				break
			}
			output.Regions = append(output.Regions, api.Region{RegionName: ptr(api.RegionName(region.Name)), RegionOptStatus: ptr(api.RegionOptStatus(status))})
		}
		return nil
	})
	return output, err
}
