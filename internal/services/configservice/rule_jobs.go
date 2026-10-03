package configservice

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

// The managed rule's documented resource types are deliberately distinct from
// the recorder's supported owner types: recording a type does not imply that
// REQUIRED_TAGS evaluates it.
// https://docs.aws.amazon.com/config/latest/developerguide/required-tags.html
var requiredTagTypes = []string{
	"AWS::ACM::Certificate", "AWS::AutoScaling::AutoScalingGroup", "AWS::CloudFormation::Stack", "AWS::CodeBuild::Project", "AWS::DynamoDB::Table",
	"AWS::EC2::CustomerGateway", "AWS::EC2::Instance", "AWS::EC2::InternetGateway", "AWS::EC2::NetworkAcl", "AWS::EC2::NetworkInterface", "AWS::EC2::RouteTable", "AWS::EC2::SecurityGroup", "AWS::EC2::Subnet", "AWS::EC2::Volume", "AWS::EC2::VPC", "AWS::EC2::VPNConnection", "AWS::EC2::VPNGateway",
	"AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::RDS::DBInstance", "AWS::RDS::DBSecurityGroup", "AWS::RDS::DBSnapshot", "AWS::RDS::DBSubnetGroup", "AWS::RDS::EventSubscription", "AWS::Redshift::Cluster", "AWS::Redshift::ClusterParameterGroup", "AWS::Redshift::ClusterSecurityGroup", "AWS::Redshift::ClusterSnapshot", "AWS::Redshift::ClusterSubnetGroup", "AWS::S3::Bucket",
}

func latestRuleItems(items []Item) []Item {
	latest := map[string]Item{}
	for _, item := range items {
		k := item.ResourceType + "\x00" + item.ResourceID
		old, ok := latest[k]
		if !ok || item.Sequence > old.Sequence {
			latest[k] = item
		}
	}
	out := make([]Item, 0, len(latest))
	for _, k := range sortedRuleKeys(latest) {
		out = append(out, latest[k])
	}
	return out
}
func ruleItemMatches(rule Rule, item Item) bool {
	if len(rule.ResourceTypes) > 0 && !slices.Contains(rule.ResourceTypes, item.ResourceType) {
		return false
	}
	if rule.ResourceID != "" && rule.ResourceID != item.ResourceID {
		return false
	}
	if rule.TagKey != "" {
		v, ok := item.Tags[rule.TagKey]
		if !ok || rule.TagValue != "" && rule.TagValue != v {
			return false
		}
	}
	return true
}
func (s *Service) evaluateItem(tx Transaction, item Item) error {
	rules, err := tx.Rules(item.Scope)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if err := s.evaluateRuleItem(tx, rule, item); err != nil {
			return err
		}
	}
	s.wake(tx.Context())
	return nil
}
func (s *Service) evaluateRuleItem(tx Transaction, rule Rule, item Item) error {
	if rule.Owner == "AWS" && !slices.Contains(requiredTagTypes, item.ResourceType) {
		return nil
	}
	if !ruleItemMatches(rule, item) {
		// A resource leaving a tag scope must clear its old compliance, rather than
		// remaining noncompliant forever. Pending runs also count as prior scope.
		previous := false
		evals, err := tx.Evaluations(item.Scope)
		if err != nil {
			return err
		}
		for _, e := range evals {
			if e.RuleName == rule.Name && e.ResourceType == item.ResourceType && e.ResourceID == item.ResourceID {
				previous = true
				break
			}
		}
		if !previous {
			history, err := tx.Items(item.Scope)
			if err != nil {
				return err
			}
			for _, old := range history {
				if old.ResourceType == item.ResourceType && old.ResourceID == item.ResourceID && old.Sequence < item.Sequence && ruleItemMatches(rule, old) {
					previous = true
					break
				}
			}
		}
		if !previous {
			return nil
		}
	}
	now := s.clock.Now()
	return tx.PutEvaluationRun(EvaluationRun{Scope: item.Scope, Token: opaqueRuleID(), RuleName: rule.Name, ItemSequence: item.Sequence, Due: now, CreatedAt: now, Status: "PENDING"})
}

func (s *Service) nextRuleJob(ctx context.Context) (scheduler.Job, bool, error) {
	var chosen EvaluationRun
	found := false
	err := s.repository.View(ctx, func(r Reader) error {
		runs, err := r.EvaluationRuns()
		if err != nil {
			return err
		}
		for _, run := range runs {
			if run.Status != "PENDING" && run.Status != "RUNNING" {
				continue
			}
			if !found || run.Due.Before(chosen.Due) || run.Due.Equal(chosen.Due) && (run.ItemSequence < chosen.ItemSequence || run.ItemSequence == chosen.ItemSequence && run.Token < chosen.Token) {
				chosen = run
				found = true
			}
		}
		return nil
	})
	if err != nil || !found {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: "rule:" + chosen.Token, Version: 1, Due: chosen.Due}, true, nil
}
func (s *Service) processRuleJob(ctx context.Context, job scheduler.Job) error {
	token := strings.TrimPrefix(job.Key, "rule:")
	var run EvaluationRun
	var rule Rule
	var item Item
	var recorder Recorder
	invoke := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		runs, err := tx.EvaluationRuns()
		if err != nil {
			return err
		}
		found := false
		for _, r := range runs {
			if r.Token == token {
				run = r
				found = true
				break
			}
		}
		if !found || (run.Status != "PENDING" && run.Status != "RUNNING") || s.clock.Now().Before(run.Due) {
			return nil
		}
		if run.Status == "RUNNING" {
			run.Status = "EXPIRED"
			run.ErrorCode = "EvaluationTimedOut"
			run.ErrorMessage = "The Lambda evaluation did not finish before its execution deadline"
			run.CompletedAt = s.clock.Now()
			return tx.PutEvaluationRun(run)
		}
		rule, err = ruleByName(tx, run.Scope, run.RuleName)
		if err != nil {
			return err
		}
		items, err := tx.Items(run.Scope)
		if err != nil {
			return err
		}
		found = false
		for _, i := range items {
			if i.Sequence == run.ItemSequence {
				item = i
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("config rule %s references missing configuration item %d", run.RuleName, run.ItemSequence)
		}
		if rule.Owner == "AWS" {
			return s.evaluateManagedRule(tx, rule, item, run)
		}
		recorder, found, err = tx.Recorder(run.Scope)
		if err != nil {
			return err
		}
		if !found {
			run.Status = "FAILED"
			run.CompletedAt = s.clock.Now()
			run.ErrorCode = "NoAvailableConfigurationRecorderException"
			run.ErrorMessage = "The recorder was deleted before rule execution"
			return tx.PutEvaluationRun(run)
		}
		run.Status = "RUNNING"
		// TODO: Comeback: calibrate late native ResultToken submissions. This bounded
		// implementation accepts callbacks only during synchronous Lambda execution,
		// with the Lambda service's maximum 15-minute runtime as a crash deadline.
		run.Due = s.clock.Now().Add(15 * time.Minute)
		if err := tx.PutEvaluationRun(run); err != nil {
			return err
		}
		invoke = true
		return nil
	})
	if err != nil || !invoke {
		return err
	}
	payload, invokeErr := ruleInvocation(rule, item, run, recorder)
	if invokeErr == nil {
		if s.effects == nil {
			invokeErr = fmt.Errorf("lambda rule execution is unavailable")
		} else {
			invokeErr = s.effects.InvokeRule(scopedContext(ctx, rule.Scope), rule, payload)
		}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		runs, err := tx.EvaluationRuns()
		if err != nil {
			return err
		}
		for _, current := range runs {
			if current.Token != token || current.Status != "RUNNING" {
				continue
			}
			hadResults := !current.CompletedAt.IsZero()
			current.CompletedAt = s.clock.Now()
			current.Status = "NO_RESULTS"
			if hadResults {
				current.Status = "SUCCEEDED"
			}
			if invokeErr != nil {
				current.Status = "FAILED"
				current.ErrorCode = "LambdaFunctionExecutionError"
				current.ErrorMessage = invokeErr.Error()
			}
			if err := tx.PutEvaluationRun(current); err != nil {
				return err
			}
			r, err := ruleByName(tx, current.Scope, current.RuleName)
			if err != nil {
				return err
			}
			r.ErrorCode = current.ErrorCode
			r.ErrorMessage = current.ErrorMessage
			return tx.PutRule(r)
		}
		return nil
	})
}
func (s *Service) evaluateManagedRule(tx Transaction, rule Rule, item Item, run EvaluationRun) error {
	kind := "COMPLIANT"
	if !ruleItemMatches(rule, item) || item.Status == "ResourceDeleted" || item.Status == "ResourceNotRecorded" {
		kind = "NOT_APPLICABLE"
	} else {
		params := map[string]string{}
		if err := json.Unmarshal([]byte(rule.InputParameters), &params); err != nil {
			return err
		}
		for n := 1; n <= 6; n++ {
			prefix := fmt.Sprintf("tag%d", n)
			key := params[prefix+"Key"]
			if key == "" {
				continue
			}
			v, ok := item.Tags[key]
			if !ok || params[prefix+"Value"] != "" && !slices.Contains(strings.Split(params[prefix+"Value"], ","), v) {
				kind = "NON_COMPLIANT"
				break
			}
		}
	}
	now := s.clock.Now()
	old, err := tx.Evaluations(item.Scope)
	if err != nil {
		return err
	}
	newer := false
	for _, e := range old {
		if e.RuleName == rule.Name && e.ResourceType == item.ResourceType && e.ResourceID == item.ResourceID && e.OrderingTime.After(item.CaptureTime) {
			newer = true
			break
		}
	}
	if !newer {
		if err := tx.PutEvaluation(Evaluation{Scope: item.Scope, RuleName: rule.Name, ResourceType: item.ResourceType, ResourceID: item.ResourceID, ComplianceType: kind, OrderingTime: item.CaptureTime, RecordedAt: now, InvokedAt: run.CreatedAt}); err != nil {
			return err
		}
	}
	rule.LastEvaluation = now
	rule.ErrorCode = ""
	rule.ErrorMessage = ""
	if err := tx.PutRule(rule); err != nil {
		return err
	}
	run.Status = "SUCCEEDED"
	run.CompletedAt = now
	return tx.PutEvaluationRun(run)
}

type ruleEventRelationship struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
	ResourceName string `json:"resourceName,omitempty"`
	Name         string `json:"name"`
}
type ruleEventItem struct {
	CaptureTime      time.Time                  `json:"configurationItemCaptureTime"`
	AccountID        string                     `json:"awsAccountId"`
	Status           string                     `json:"configurationItemStatus"`
	ResourceID       string                     `json:"resourceId"`
	ResourceName     string                     `json:"resourceName,omitempty"`
	ARN              string                     `json:"ARN"`
	Region           string                     `json:"awsRegion"`
	AvailabilityZone string                     `json:"availabilityZone,omitempty"`
	ResourceType     string                     `json:"resourceType"`
	Version          string                     `json:"configurationItemVersion"`
	Sequence         int64                      `json:"configurationStateId"`
	CreationTime     *time.Time                 `json:"resourceCreationTime,omitempty"`
	Tags             map[string]string          `json:"tags,omitempty"`
	Relationships    []ruleEventRelationship    `json:"relationships,omitempty"`
	Configuration    json.RawMessage            `json:"configuration,omitempty"`
	Supplementary    map[string]json.RawMessage `json:"supplementaryConfiguration,omitempty"`
}

func ruleInvocation(rule Rule, item Item, run EvaluationRun, recorder Recorder) ([]byte, error) {
	// The Lambda invocation shape is not the Config API shape: awsAccountId,
	// ARN, object-valued configuration and relationship.name are native fields.
	// https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_lambda-functions.html
	ci := ruleEventItem{CaptureTime: item.CaptureTime, AccountID: item.AccountID, Status: item.Status, ResourceID: item.ResourceID, ResourceName: item.ResourceName, ARN: item.ARN, Region: item.Region, AvailabilityZone: item.AvailabilityZone, ResourceType: item.ResourceType, Version: "1.3", Sequence: item.Sequence, Tags: item.Tags, Configuration: json.RawMessage(item.Configuration)}
	if !item.CreationTime.IsZero() {
		ci.CreationTime = &item.CreationTime
	}
	for _, r := range item.Relationships {
		ci.Relationships = append(ci.Relationships, ruleEventRelationship{r.ResourceID, r.ResourceType, r.ResourceName, r.Name})
	}
	if len(item.Supplementary) > 0 {
		ci.Supplementary = make(map[string]json.RawMessage, len(item.Supplementary))
		for k, v := range item.Supplementary {
			ci.Supplementary[k] = json.RawMessage(v)
		}
	}
	invoking := struct {
		Item        *ruleEventItem `json:"configurationItem,omitempty"`
		Summary     *ruleEventItem `json:"configurationItemSummary,omitempty"`
		MessageType string         `json:"messageType"`
		CreatedAt   time.Time      `json:"notificationCreationTime"`
	}{Item: &ci, MessageType: "ConfigurationItemChangeNotification", CreatedAt: run.CreatedAt}
	data, err := json.Marshal(invoking)
	if err != nil {
		return nil, err
	}
	if len(data) > 256*1024 {
		if !slices.Contains(rule.SourceMessages, "OversizedConfigurationItemChangeNotification") {
			return nil, fmt.Errorf("the rule source does not accept oversized configuration items")
		}
		ci.Configuration = nil
		ci.Tags = nil
		ci.Relationships = nil
		ci.Supplementary = nil
		invoking.Item = nil
		invoking.Summary = &ci
		invoking.MessageType = "OversizedConfigurationItemChangeNotification"
		data, err = json.Marshal(invoking)
		if err != nil {
			return nil, err
		}
	}
	params := rule.InputParameters
	if params == "" {
		params = "{}"
	}
	return json.Marshal(struct {
		InvokingEvent    string `json:"invokingEvent"`
		RuleParameters   string `json:"ruleParameters"`
		ResultToken      string `json:"resultToken"`
		EventLeftScope   bool   `json:"eventLeftScope"`
		ExecutionRoleARN string `json:"executionRoleArn"`
		RuleARN          string `json:"configRuleArn"`
		RuleName         string `json:"configRuleName"`
		RuleID           string `json:"configRuleId"`
		AccountID        string `json:"accountId"`
		Version          string `json:"version"`
	}{string(data), params, run.Token, !ruleItemMatches(rule, item), recorder.RoleARN, rule.ARN, rule.Name, rule.ID, rule.AccountID, "1.0"})
}

// Keep job order independent of map iteration when callers batch retained items.
func sortRuleItems(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].AccountID != items[j].AccountID {
			return items[i].AccountID < items[j].AccountID
		}
		if items[i].Region != items[j].Region {
			return items[i].Region < items[j].Region
		}
		if items[i].ResourceType != items[j].ResourceType {
			return items[i].ResourceType < items[j].ResourceType
		}
		return items[i].ResourceID < items[j].ResourceID
	})
}
