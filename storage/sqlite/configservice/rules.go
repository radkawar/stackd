package configservice

import (
	"encoding/json"
	domain "stackd/storage/configservice"
	"stackd/storage/sqlite/configservice/internal/sqlcgen"
)

func (r reader) loadRule(v sqlcgen.ConfigRule) (domain.Rule, error) {
	out := domain.Rule{CFNOwnership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}, Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, ID: v.ID, ARN: v.ARN, Description: v.Description, Owner: v.Owner, SourceIdentifier: v.SourceIdentifier, ResourceID: v.ResourceID, TagKey: v.TagKey, TagValue: v.TagValue, CreatedAt: v.CreatedAt, LastEvaluation: v.LastEvaluation, LastReevaluation: v.LastReevaluation, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage}
	types, err := r.q.ListRuleTypes(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, t := range types {
		out.ResourceTypes = append(out.ResourceTypes, t.ResourceType)
	}
	messages, err := r.q.ListRuleMessages(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, m := range messages {
		out.SourceMessages = append(out.SourceMessages, m.Message)
	}
	if v.ParametersPresent {
		parameters, err := r.q.ListRuleParameters(r.ctx, v.RowID)
		if err != nil {
			return out, err
		}
		values := make(map[string]string, len(parameters))
		for _, p := range parameters {
			values[p.ParameterKey] = p.Value
		}
		data, err := json.Marshal(values)
		if err != nil {
			return out, err
		}
		out.InputParameters = string(data)
	}
	return out, nil
}

func (r reader) Rules(s domain.Scope) ([]domain.Rule, error) {
	rows, err := r.q.ListRules(r.ctx, sqlcgen.ListRulesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Rule, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadRule(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutRule(v domain.Rule) error {
	var parameters map[string]string
	if v.InputParameters != "" {
		if err := json.Unmarshal([]byte(v.InputParameters), &parameters); err != nil {
			return err
		}
	}
	id, err := w.q.PutRule(w.ctx, sqlcgen.PutRuleParams{CfnOwner: v.CFNOwnership.Owner, CfnToken: v.CFNOwnership.Token, Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, Name: v.Name, ID: v.ID, ARN: v.ARN, Description: v.Description, Owner: v.Owner, SourceIdentifier: v.SourceIdentifier, ParametersPresent: v.InputParameters != "", ResourceID: v.ResourceID, TagKey: v.TagKey, TagValue: v.TagValue, CreatedAt: v.CreatedAt, LastEvaluation: v.LastEvaluation, LastReevaluation: v.LastReevaluation, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage})
	if err != nil {
		return err
	}
	if err = w.q.ClearRuleTypes(w.ctx, id); err != nil {
		return err
	}
	if err = w.q.ClearRuleMessages(w.ctx, id); err != nil {
		return err
	}
	if err = w.q.ClearRuleParameters(w.ctx, id); err != nil {
		return err
	}
	for ordinal, t := range v.ResourceTypes {
		if err = w.q.InsertRuleType(w.ctx, sqlcgen.InsertRuleTypeParams{ParentID: id, Ordinal: int64(ordinal), ResourceType: t}); err != nil {
			return err
		}
	}
	for ordinal, message := range v.SourceMessages {
		if err = w.q.InsertRuleMessage(w.ctx, sqlcgen.InsertRuleMessageParams{ParentID: id, Ordinal: int64(ordinal), Message: message}); err != nil {
			return err
		}
	}
	for key, value := range parameters {
		if err = w.q.InsertRuleParameter(w.ctx, sqlcgen.InsertRuleParameterParams{ParentID: id, ParameterKey: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteRule(s domain.Scope, name string) error {
	if err := w.DeleteEvaluations(s, name); err != nil {
		return err
	}
	if err := w.q.DeleteEvaluationRuns(w.ctx, sqlcgen.DeleteEvaluationRunsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, RuleName: name}); err != nil {
		return err
	}
	return w.q.DeleteRule(w.ctx, sqlcgen.DeleteRuleParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Name: name})
}

func (r reader) loadEvaluation(v sqlcgen.ConfigEvaluation) (domain.Evaluation, error) {
	out := domain.Evaluation{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, RuleName: v.RuleName, ResourceType: v.ResourceType, ResourceID: v.ResourceID, ComplianceType: v.ComplianceType, Annotation: v.Annotation, OrderingTime: v.OrderingTime, RecordedAt: v.RecordedAt, InvokedAt: v.InvokedAt}
	return out, nil
}

func (r reader) Evaluations(s domain.Scope) ([]domain.Evaluation, error) {
	rows, err := r.q.ListEvaluations(r.ctx, sqlcgen.ListEvaluationsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Evaluation, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadEvaluation(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutEvaluation(v domain.Evaluation) error {
	return w.q.PutEvaluation(w.ctx, sqlcgen.PutEvaluationParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, RuleName: v.RuleName, ResourceType: v.ResourceType, ResourceID: v.ResourceID, ComplianceType: v.ComplianceType, Annotation: v.Annotation, OrderingTime: v.OrderingTime, RecordedAt: v.RecordedAt, InvokedAt: v.InvokedAt})
}

func (r reader) loadEvaluationRun(v sqlcgen.ConfigEvaluationRun) (domain.EvaluationRun, error) {
	out := domain.EvaluationRun{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Token: v.Token, RuleName: v.RuleName, ItemSequence: v.ItemSequence, Due: v.Due, CreatedAt: v.CreatedAt, CompletedAt: v.CompletedAt, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage}
	return out, nil
}

func (r reader) EvaluationRuns() ([]domain.EvaluationRun, error) {
	rows, err := r.q.ListEvaluationRuns(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.EvaluationRun, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadEvaluationRun(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutEvaluationRun(v domain.EvaluationRun) error {
	return w.q.PutEvaluationRun(w.ctx, sqlcgen.PutEvaluationRunParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, Token: v.Token, RuleName: v.RuleName, ItemSequence: v.ItemSequence, Due: v.Due, CreatedAt: v.CreatedAt, CompletedAt: v.CompletedAt, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage})
}

func (w writer) DeleteEvaluations(s domain.Scope, name string) error {
	return w.q.DeleteEvaluations(w.ctx, sqlcgen.DeleteEvaluationsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, RuleName: name})
}
