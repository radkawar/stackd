package resourcegroups

import (
	"context"
	"encoding/json"
	"fmt"

	api "stackd/internal/awsapi/resourcegroups"
)

// Query field names are case sensitive in Resource Groups, unlike encoding/json's
// default struct matching. Decode the small query grammar explicitly.
func (q *resourceQuery) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for k, v := range fields {
		var err error
		switch k {
		case "ResourceTypeFilters":
			err = json.Unmarshal(v, &q.ResourceTypeFilters)
		case "TagFilters":
			err = json.Unmarshal(v, &q.TagFilters)
		case "StackIdentifier":
			err = json.Unmarshal(v, &q.StackIdentifier)
		default:
			return fmt.Errorf("unknown query field %q", k)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (f *tagFilter) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for k, v := range fields {
		var err error
		switch k {
		case "Key":
			err = json.Unmarshal(v, &f.Key)
		case "Values":
			err = json.Unmarshal(v, &f.Values)
		default:
			return fmt.Errorf("unknown tag filter field %q", k)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) validateQuery(ctx context.Context, in *api.ResourceQuery) error {
	q, err := parseQuery(in)
	if err != nil {
		return err
	}
	if *in.Type != api.QueryTypeCLOUDFORMATION_STACK_1_0 {
		return nil
	}
	if s.resources == nil {
		return failure("NotImplementedException", "Current CloudFormation discovery is not configured.")
	}
	stack, err := s.resources.Stack(ctx, q.StackIdentifier)
	if err != nil {
		return err
	}
	if stack.ARN == "" {
		return failure("BadRequestException", "The specified CloudFormation stack does not exist.")
	}
	switch stack.Status {
	case "DELETE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED":
		return failure("BadRequestException", "The specified CloudFormation stack cannot have the following statuses: DELETE_COMPLETE, ROLLBACK_COMPLETE, CREATE_FAILED.")
	}
	return nil
}
