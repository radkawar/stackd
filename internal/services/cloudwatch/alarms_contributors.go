package cloudwatch

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func alarmContributorQuery(config *MetricAlarmConfig) (*insightsQuery, *awswire.Error) {
	if config == nil {
		return nil, nil
	}
	for _, query := range config.Queries {
		if query.ReturnData != nil && !*query.ReturnData || !isInsightsExpression(query.Expression) {
			continue
		}
		insights, w := parseInsights(query.Expression)
		if w != nil {
			return nil, w
		}
		if len(insights.group) > 0 {
			return insights, nil
		}
	}
	return nil, nil
}

func contributorAttributes(attributes map[string]string) api.ContributorAttributes {
	out := make(api.ContributorAttributes, len(attributes))
	for name, value := range attributes {
		out[api.AttributeName(name)] = api.AttributeValue(value)
	}
	return out
}

type alarmContributorCursor struct {
	AlarmID string
	AfterID string
}

func (s *Service) describeAlarmContributors(tx Transaction, in *api.DescribeAlarmContributorsInput) (*api.DescribeAlarmContributorsOutput, *awswire.Error) {
	name := value(in.AlarmName)
	if w := s.authorizeAlarmRead(tx, "DescribeAlarmContributors", []string{name}, false); w != nil {
		return nil, w
	}
	alarm, err := tx.Alarm(AlarmKey{Scope: scopeFor(tx.Context()), Name: name})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ResourceNotFoundException", "No alarm for name "+name+" was found")
	}
	if err != nil {
		return nil, wireError(err)
	}
	insights, w := alarmContributorQuery(alarm.Metric)
	if w != nil {
		return nil, w
	}
	if insights == nil {
		return nil, alarmInvalid("Alarm " + name + " is not a multi time series alarm")
	}
	const limit = 100
	query := AlarmContributorQuery{AlarmID: alarm.ID, Limit: limit + 1}
	if in.NextToken != nil {
		encoded, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		var cursor alarmContributorCursor
		if err != nil || json.Unmarshal(encoded, &cursor) != nil || cursor.AlarmID != alarm.ID || cursor.AfterID == "" {
			return nil, failure("InvalidNextToken", "Invalid NextToken : "+value(in.NextToken))
		}
		query.AfterID = cursor.AfterID
	}
	contributors, err := tx.AlarmContributors(query)
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.DescribeAlarmContributorsOutput{AlarmContributors: api.AlarmContributors{}}
	if len(contributors) > limit {
		encoded, _ := json.Marshal(alarmContributorCursor{AlarmID: alarm.ID, AfterID: contributors[limit-1].ID})
		out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString(encoded)))
		contributors = contributors[:limit]
	}
	for _, contributor := range contributors {
		out.AlarmContributors = append(out.AlarmContributors, api.AlarmContributor{
			ContributorId: new(api.ContributorId(contributor.ID)), ContributorAttributes: contributorAttributes(contributor.Attributes),
			StateReason: new(api.StateReason(contributor.Reason)), StateTransitionedTimestamp: new(api.Timestamp(contributor.Transitioned)),
		})
	}
	return out, nil
}
