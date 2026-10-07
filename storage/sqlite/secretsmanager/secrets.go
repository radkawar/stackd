package secretsmanager

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/secretsmanager"
	domain "stackd/storage/secretsmanager"
	"stackd/storage/sqlite/secretsmanager/internal/sqlcgen"
)

func (r reader) secret(v sqlcgen.SecretsmanagerSecret) (domain.SecretRecord, error) {
	out := domain.SecretRecord{
		Key: domain.SecretKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name},
		ARN: v.Arn, Type: v.Type, Description: stringPointer[string](v.Description),
		KMSKeyID: v.KmsKeyID, OwningService: v.OwningService, Created: v.Created, Changed: v.Changed,
		LastAccessed: timePointer(v.LastAccessed), Deleted: timePointer(v.Deleted), DeleteAfter: timePointer(v.DeleteAfter),
		RotationEnabled: boolPointer(v.RotationEnabled), RotationLambdaARN: v.RotationLambdaArn,
		LastRotated: timePointer(v.LastRotated), NextRotation: timePointer(v.NextRotation),
		RotationDue: timePointer(v.RotationDue), PrimaryRegion: v.PrimaryRegion,
		Ownership:           domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken},
		PolicyOwnership:     domain.CloudFormationOwnership{Owner: v.PolicyOwner, Token: v.PolicyToken},
		RotationOwnership:   domain.CloudFormationOwnership{Owner: v.RotationOwner, Token: v.RotationToken},
		AttachmentOwnership: domain.CloudFormationOwnership{Owner: v.AttachmentOwner, Token: v.AttachmentToken},
		AttachmentMetadata:  domain.SecretTargetMetadata{Engine: v.AttachmentEngine, Host: v.AttachmentHost, Port: v.AttachmentPort, DBInstanceIdentifier: v.AttachmentDbInstance, DBClusterIdentifier: v.AttachmentDbCluster},
	}
	out.Policy.Document, out.Policy.TrustPolicy = v.PolicyDocument, v.PolicyTrust
	if v.TagsPresent {
		rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SecretName: v.Name})
		if err != nil {
			return domain.SecretRecord{}, err
		}
		out.Tags = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Tags[row.Key] = row.Value
		}
	}
	if v.PolicyPrincipalsPresent {
		rows, err := r.q.ListPolicyPrincipals(r.ctx, sqlcgen.ListPolicyPrincipalsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SecretName: v.Name})
		if err != nil {
			return domain.SecretRecord{}, err
		}
		out.Policy.PrincipalIDs = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Policy.PrincipalIDs[row.Arn] = row.PrincipalID
		}
	}
	rules, err := r.q.GetRotationRules(r.ctx, sqlcgen.GetRotationRulesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SecretName: v.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return domain.SecretRecord{}, err
	}
	out.RotationRules = &api.RotationRulesType{
		Duration:           stringPointer[api.DurationType](rules.Duration),
		ScheduleExpression: stringPointer[api.ScheduleExpressionType](rules.ScheduleExpression),
	}
	if rules.AutomaticallyAfterDays.Valid {
		out.RotationRules.AutomaticallyAfterDays = new(api.AutomaticallyRotateAfterDaysType(rules.AutomaticallyAfterDays.Int64))
	}
	return out, nil
}

func (r reader) Secret(k domain.SecretKey) (domain.SecretRecord, error) {
	v, err := r.q.GetSecret(r.ctx, sqlcgen.GetSecretParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.SecretRecord{}, missing(err)
	}
	return r.secret(v)
}

func (r reader) Secrets(k domain.Scope) ([]domain.SecretRecord, error) {
	rows, err := r.q.ListSecrets(r.ctx, sqlcgen.ListSecretsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.SecretRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.secret(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) NextDeletion() (domain.SecretRecord, error) {
	v, err := r.q.NextDeletion(r.ctx)
	if err != nil {
		return domain.SecretRecord{}, missing(err)
	}
	return r.secret(v)
}

func (r reader) NextScheduledRotation() (domain.SecretRecord, error) {
	v, err := r.q.NextScheduledRotation(r.ctx)
	if err != nil {
		return domain.SecretRecord{}, missing(err)
	}
	return r.secret(v)
}

func (w writer) PutSecret(v domain.SecretRecord) error {
	k := v.Key
	if err := w.q.PutSecret(w.ctx, sqlcgen.PutSecretParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		Arn: v.ARN, Type: v.Type, Description: nullableString(v.Description),
		KmsKeyID: v.KMSKeyID, OwningService: v.OwningService, Created: v.Created.UTC(), Changed: v.Changed.UTC(),
		LastAccessed: nullableTime(v.LastAccessed), Deleted: nullableTime(v.Deleted), DeleteAfter: nullableTime(v.DeleteAfter),
		TagsPresent: v.Tags != nil, PolicyDocument: v.Policy.Document,
		PolicyPrincipalsPresent: v.Policy.PrincipalIDs != nil, PolicyTrust: v.Policy.TrustPolicy,
		RotationEnabled: nullableBool(v.RotationEnabled), RotationLambdaArn: v.RotationLambdaARN,
		LastRotated: nullableTime(v.LastRotated), NextRotation: nullableTime(v.NextRotation),
		RotationDue: nullableTime(v.RotationDue), PrimaryRegion: v.PrimaryRegion,
		CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token,
		PolicyOwner: v.PolicyOwnership.Owner, PolicyToken: v.PolicyOwnership.Token,
		RotationOwner: v.RotationOwnership.Owner, RotationToken: v.RotationOwnership.Token,
		AttachmentOwner: v.AttachmentOwnership.Owner, AttachmentToken: v.AttachmentOwnership.Token,
		AttachmentEngine: v.AttachmentMetadata.Engine, AttachmentHost: v.AttachmentMetadata.Host, AttachmentPort: v.AttachmentMetadata.Port,
		AttachmentDbInstance: v.AttachmentMetadata.DBInstanceIdentifier, AttachmentDbCluster: v.AttachmentMetadata.DBClusterIdentifier,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeletePolicyPrincipals(w.ctx, sqlcgen.DeletePolicyPrincipalsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name}); err != nil {
		return err
	}
	for arn, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutPolicyPrincipal(w.ctx, sqlcgen.PutPolicyPrincipalParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name, Arn: arn, PrincipalID: id}); err != nil {
			return err
		}
	}
	if v.RotationRules == nil {
		return w.q.DeleteRotationRules(w.ctx, sqlcgen.DeleteRotationRulesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name})
	}
	rules := v.RotationRules
	var days sql.NullInt64
	if rules.AutomaticallyAfterDays != nil {
		days = sql.NullInt64{Int64: int64(*rules.AutomaticallyAfterDays), Valid: true}
	}
	return w.q.PutRotationRules(w.ctx, sqlcgen.PutRotationRulesParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SecretName: k.Name,
		AutomaticallyAfterDays: days, Duration: nullableString(rules.Duration), ScheduleExpression: nullableString(rules.ScheduleExpression),
	})
}

func (w writer) DeleteSecret(k domain.SecretKey) error {
	return w.q.DeleteSecret(w.ctx, sqlcgen.DeleteSecretParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
