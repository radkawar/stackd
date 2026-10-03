package cloudtrail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type continuation struct {
	Selection   string
	Start, End  time.Time
	Before      journal.APICallCursor
	MaxSequence int64
}

func (s *Service) lookup(ctx context.Context, in *api.LookupEventsInput) (*api.LookupEventsOutput, *awswire.Error) {
	if err := s.authorizer.Authorize(ctx, authorization.Request{Action: "cloudtrail:LookupEvents", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	// TODO: Comeback enforce CloudTrail's measured per-account/region lookup throttling and native publication delay; these require separate behavioral captures from management-event retention.
	if in.EventCategory != nil {
		if *in.EventCategory != api.EventCategoryInsight {
			return nil, failure("InvalidEventCategoryException", "Invalid event category.")
		}
		return nil, failure("UnsupportedOperationException", "CloudTrail Insights event history is not implemented.")
	}
	if len(in.LookupAttributes) > 1 {
		return nil, failure("InvalidLookupAttributesException", "Only one lookup attribute is supported.")
	}
	m := awsctx.FromContext(ctx)
	now := s.clock.Now().UTC()
	q := journal.APICallQuery{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, Start: now.AddDate(0, 0, -90), End: now, Limit: 51}
	if in.StartTime != nil && in.EndTime != nil && in.StartTime.After(*in.EndTime) {
		return nil, failure("InvalidTimeRangeException", "StartTime must not be after EndTime.")
	}
	if in.StartTime != nil && in.EndTime == nil && in.StartTime.After(now) {
		return nil, failure("InvalidTimeRangeException", "StartTime must not be after the current time when EndTime is omitted.")
	}
	if in.StartTime != nil && in.StartTime.After(q.Start) {
		q.Start = in.StartTime.UTC()
	}
	if in.EndTime != nil && in.EndTime.Before(q.End) {
		q.End = in.EndTime.UTC()
	}
	if in.MaxResults != nil {
		q.Limit = int(*in.MaxResults) + 1
	}
	if len(in.LookupAttributes) == 1 {
		a := in.LookupAttributes[0]
		q.AttributeKey, q.AttributeValue = string(*a.AttributeKey), string(*a.AttributeValue)
		if q.AttributeKey == "ReadOnly" && q.AttributeValue != "true" && q.AttributeValue != "false" {
			return nil, failure("InvalidLookupAttributesException", "ReadOnly must be true or false.")
		}
	}
	selectionInput := *in
	selectionInput.NextToken = nil
	selection, err := json.Marshal(struct {
		Partition, Account, Region string
		Input                      api.LookupEventsInput
	}{m.Partition, m.AccountID, m.Region, selectionInput})
	if err != nil {
		return nil, failure("InvalidTimeRangeException", "A timestamp is outside the supported range.")
	}
	if in.NextToken != nil {
		data, err := base64.RawURLEncoding.DecodeString(string(*in.NextToken))
		var mark continuation
		if err != nil || json.Unmarshal(data, &mark) != nil || mark.Selection != string(selection) || mark.Before.Sequence <= 0 || mark.MaxSequence < mark.Before.Sequence || mark.Before.At.Before(mark.Start) || mark.Before.At.After(mark.End) {
			return nil, failure("InvalidNextTokenException", "Invalid pagination token.")
		}
		// Keep the original query window while enforcing the current retention floor.
		if mark.Start.After(q.Start) {
			q.Start = mark.Start
		}
		q.End = mark.End
		q.Before = &mark.Before
		q.MaxSequence = mark.MaxSequence
	}
	page, err := s.journal.LookupAPICalls(ctx, q)
	if err != nil {
		return nil, storageFailure()
	}
	out := &api.LookupEventsOutput{Events: api.EventsList{}}
	count := q.Limit - 1
	if len(page.Events) > count {
		last := page.Events[count-1]
		encoded, err := json.Marshal(continuation{Selection: string(selection), Start: q.Start, End: q.End, Before: journal.APICallCursor{At: last.At, Sequence: last.Sequence}, MaxSequence: page.MaxSequence})
		if err != nil {
			return nil, storageFailure()
		}
		token := api.NextToken(base64.RawURLEncoding.EncodeToString(encoded))
		out.NextToken = &token
		page.Events = page.Events[:count]
	}
	for _, event := range page.Events {
		row, err := historyEvent(event)
		if err != nil {
			return nil, storageFailure()
		}
		out.Events = append(out.Events, row)
	}
	return out, nil
}
