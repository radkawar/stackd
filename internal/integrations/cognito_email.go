package integrations

import (
	"context"
	"errors"
	"slices"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cognitoidp"
	"stackd/internal/services/iam"
	"stackd/internal/services/sesv2"
	"strings"
)

const cognitoEmailPrincipal = "email.cognito-idp.amazonaws.com"
const cognitoEmailRole = "AWSServiceRoleForAmazonCognitoIdpEmailService"

// CognitoEmail keeps managed default mail separate from current DEVELOPER role
// sessions. SES admission joins the user's transaction; MIME capture follows it.
type CognitoEmail struct {
	SES         *sesv2.Service
	Roles       ServiceRoles
	Provisioner interface {
		EnsureServiceLinkedRole(context.Context, string) error
	}
	sessions serviceRoleSessions
}

func (a *CognitoEmail) PrepareEmail(ctx context.Context, pool cognitoidp.PoolKey, c cognitoidp.EmailConfiguration) error {
	if a.SES == nil || a.Provisioner == nil {
		return errors.New("cognito SES delivery is not configured")
	}
	if c.SendingAccount != "DEVELOPER" {
		return nil
	}
	if err := a.Provisioner.EnsureServiceLinkedRole(ctx, cognitoEmailPrincipal); err != nil {
		return err
	}
	from := c.From
	if from == "" {
		_, from, _ = strings.Cut(c.SourceARN, ":identity/")
	}
	err := a.SES.ValidateCognitoIdentity(ctx, sesv2.Scope{Partition: pool.Partition, AccountID: pool.AccountID, Region: pool.Region}, c.SourceARN, from, c.ConfigurationSet)
	var rejected *awswire.Error
	if errors.As(err, &rejected) && rejected.Code == "NotFoundException" {
		// SourceArn must identify a verified SES sender; an absent sender or
		// configuration set is invalid pool configuration, not a storage fault.
		// TODO: Comeback — capture native Cognito missing-identity/configuration
		// error codes; this modeled client error is documentation-derived.
		return &awswire.Error{Code: "InvalidParameterException", Message: rejected.Message, StatusCode: 400}
	}
	return err
}
func (a *CognitoEmail) QueueEmail(ctx context.Context, m cognitoidp.EmailMessage) error {
	if a.SES == nil {
		return errors.New("cognito SES delivery is not configured")
	}
	scope := sesv2.Scope{Partition: m.Pool.Partition, AccountID: m.Pool.AccountID, Region: m.Pool.Region}
	if m.Configuration.SendingAccount != "DEVELOPER" {
		return a.SES.QueueCognitoDefault(ctx, scope, m.To, m.Subject, m.Text)
	}
	// The unsigned Cognito caller never supplies SES IAM authority. Re-resolve the
	// actual protected role and trust on every send through the shared session owner.
	metadata := awsctx.FromContext(ctx)
	metadata.Partition = m.Pool.Partition
	metadata.AccountID = m.Pool.AccountID
	metadata.Region = m.Pool.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	role := "arn:" + m.Pool.Partition + ":iam::" + m.Pool.AccountID + ":role/aws-service-role/" + cognitoEmailPrincipal + "/" + cognitoEmailRole
	execution, err := a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: cognitoEmailPrincipal, SourceARN: m.Pool.ARN(), Type: "AWSService"}, role, "CognitoEmail", "")
	if err != nil {
		return err
	}
	c := m.Configuration
	from := c.From
	if from == "" {
		_, from, _ = strings.Cut(c.SourceARN, ":identity/")
	}
	in := &api.SendEmailInput{FromEmailAddress: new(api.EmailAddress(from)), FromEmailAddressIdentityArn: new(api.AmazonResourceName(c.SourceARN)), Destination: &api.Destination{ToAddresses: api.EmailAddressList{api.EmailAddress(m.To)}}, Content: &api.EmailContent{Simple: &api.Message{Subject: &api.Content{Data: new(api.MessageData(m.Subject))}, Body: &api.Body{Text: &api.Content{Data: new(api.MessageData(m.Text))}}}}}
	if c.ConfigurationSet != "" {
		in.ConfigurationSetName = new(api.ConfigurationSetName(c.ConfigurationSet))
	}
	if c.ReplyTo != "" {
		in.ReplyToAddresses = api.EmailAddressList{api.EmailAddress(c.ReplyTo)}
	}
	model, _ := awscatalog.LookupService("sesv2")
	operation, _ := model.Operation("SendEmail")
	_, rejected := a.SES.ExecuteCommand(execution, awsapi.DecodedRequest{Operation: operation, Input: in})
	if rejected != nil {
		return rejected
	}
	return nil
}
func CognitoEmailRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: cognitoEmailPrincipal, RoleName: cognitoEmailRole,
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"email.cognito-idp.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonCognitoIdpEmailServiceRolePolicy"},
		UsageFailureReason: "The role is in use by Cognito user pools configured for SES developer email.",
		Sources:            []string{"https://docs.aws.amazon.com/cognito/latest/developerguide/using-service-linked-roles.html", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonCognitoIdpEmailServiceRolePolicy.html"},
	}
}

type CognitoEmailRoleUsage struct {
	Pools interface {
		WithEmailRoleUsage(context.Context, string, string, func(context.Context, []cognitoidp.PoolKey) error) error
	}
}

func (a CognitoEmailRoleUsage) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.Pools.WithEmailRoleUsage(ctx, ref.Scope.Partition, ref.Scope.AccountID, func(ctx context.Context, pools []cognitoidp.PoolKey) error {
		regions := map[string][]string{}
		for _, p := range pools {
			regions[p.Region] = append(regions[p.Region], p.ARN())
		}
		out := make([]iam.ServiceLinkedRoleUsage, 0, len(regions))
		for region, arns := range regions {
			slices.Sort(arns)
			out = append(out, iam.ServiceLinkedRoleUsage{Region: region, ResourceARNs: arns})
		}
		slices.SortFunc(out, func(a, b iam.ServiceLinkedRoleUsage) int { return strings.Compare(a.Region, b.Region) })
		return fn(ctx, out)
	})
}
