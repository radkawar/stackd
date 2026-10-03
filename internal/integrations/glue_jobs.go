package integrations

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"stackd/clock"
	runtime "stackd/compute/glue"
	"stackd/internal/awsapi"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	logsapi "stackd/internal/awsapi/logs"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/glue"
	"stackd/internal/services/s3"
)

type GlueJobS3 interface {
	GetObject(context.Context, *s3api.GetObjectInput) (*s3.ObjectResponse[s3api.GetObjectOutput], *awswire.Error)
}
type GlueJobLogs interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	CreateLogGroup(context.Context, *logsapi.CreateLogGroupRequest) (*logsapi.CreateLogGroupOutput, *awswire.Error)
	CreateLogStream(context.Context, *logsapi.CreateLogStreamRequest) (*logsapi.CreateLogStreamOutput, *awswire.Error)
	PutLogEvents(context.Context, *logsapi.PutLogEventsRequest) (*logsapi.PutLogEventsResponse, *awswire.Error)
}

// GlueJobs delegates credentials to the existing service-role authority. Scripts
// enter the ordinary S3 GetObject command, including current IAM and KMS checks.
type GlueJobMetrics interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}
type GlueJobs struct {
	Roles    ServiceRoles
	S3       GlueJobS3
	Logs     GlueJobLogs
	Metrics  GlueJobMetrics
	Clock    clock.Clock
	sessions serviceRoleSessions
}

func glueJobContext(ctx context.Context, key glue.ResourceKey) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = key.Partition, key.AccountID, key.Region
	return awsctx.WithMetadata(ctx, m)
}
func glueJobPrincipal(key glue.ResourceKey) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{Name: "glue.amazonaws.com", SourceARN: key.ARN("job"), Type: "AWSService"}
}
func (a *GlueJobs) Prepare(ctx context.Context, job glue.JobRecord, run glue.JobRunRecord) (glue.JobExecutionInput, error) {
	if a.S3 == nil {
		return glue.JobExecutionInput{}, errors.New("glue S3 integration is not configured")
	}
	ctx = glueJobContext(ctx, job.Key)
	credential, rejected := a.Roles.assume(ctx, glueJobPrincipal(job.Key), job.Role, identity.RoleSessionSpec{SessionName: "GlueJobRunnerSession", Duration: time.Hour}, "")
	if rejected != nil {
		return glue.JobExecutionInput{}, rejected
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, job.Key.Region, "glue.amazonaws.com")
	if rejected != nil {
		return glue.JobExecutionInput{}, rejected
	}
	u, err := url.Parse(job.ScriptLocation)
	if err != nil {
		return glue.JobExecutionInput{}, err
	}
	output, rejected := a.S3.GetObject(ctx, &s3api.GetObjectInput{Bucket: new(s3api.BucketName(u.Host)), Key: new(s3api.ObjectKey(strings.TrimPrefix(u.Path, "/")))})
	if rejected != nil {
		return glue.JobExecutionInput{}, rejected
	}
	return glue.JobExecutionInput{Script: output.Output.Body}, nil
}
func (a *GlueJobs) Credentials(ctx context.Context, run glue.JobRunRecord) (runtime.Credentials, error) {
	ctx = glueJobContext(ctx, run.Key)
	credential, rejected := a.Roles.assume(ctx, glueJobPrincipal(run.Key), run.Role, identity.RoleSessionSpec{SessionName: "GlueJobRunnerSession", Duration: time.Hour}, "")
	if rejected != nil {
		return runtime.Credentials{}, rejected
	}
	return runtime.Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken, Expiration: credential.Expiration}, nil
}
func (a *GlueJobs) Publish(ctx context.Context, run glue.JobRunRecord, output string) error {
	if a.Logs == nil {
		return errors.New("glue Logs integration is not configured")
	}
	ctx = glueJobContext(ctx, run.Key)
	ctx, err := a.sessions.context(ctx, a.Roles, glueJobPrincipal(run.Key), run.Role, "GlueJobLogs", "")
	if err != nil {
		return err
	}
	prefix := "/aws-glue/jobs"
	if run.Command == "pythonshell" {
		prefix = "/aws-glue/python-jobs"
	}
	if custom := run.Arguments["--custom-logGroup-prefix"]; custom != "" {
		prefix = custom
	}
	if run.LogsKMSKeyARN != "" {
		prefix += "/" + run.SecurityConfiguration + "-role/" + run.Role[strings.LastIndex(run.Role, "/")+1:]
	}
	if err := a.publishOutput(ctx, run, prefix+"/output", output); err != nil {
		return err
	}
	if err := a.publishOutput(ctx, run, prefix+"/error", run.ErrorOutput); err != nil {
		return err
	}
	return nil
}
func (a *GlueJobs) publishOutput(ctx context.Context, run glue.JobRunRecord, group, output string) error {
	if output == "" {
		return nil
	}
	_, rejected := a.Logs.CreateLogGroup(ctx, &logsapi.CreateLogGroupRequest{LogGroupName: new(logsapi.LogGroupName(group))})
	if rejected != nil && rejected.Code != "ResourceAlreadyExistsException" {
		return rejected
	}
	if run.LogsKMSKeyARN != "" {
		model, _ := awscatalog.LookupService("logs")
		operation, _ := model.Operation("AssociateKmsKey")
		_, rejected = a.Logs.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &logsapi.AssociateKmsKeyRequest{LogGroupName: new(logsapi.LogGroupName(group)), KmsKeyId: new(logsapi.KmsKeyId(run.LogsKMSKeyARN))}})
		if rejected != nil {
			return rejected
		}
	}
	stream := run.ID
	if custom := run.Arguments["--custom-logStream-prefix"]; custom != "" {
		stream = custom
	}
	if run.Command == "glueetl" {
		stream += "-driver"
	}
	_, rejected = a.Logs.CreateLogStream(ctx, &logsapi.CreateLogStreamRequest{LogGroupName: new(logsapi.LogGroupName(group)), LogStreamName: new(logsapi.LogStreamName(stream))})
	if rejected != nil && rejected.Code != "ResourceAlreadyExistsException" {
		return rejected
	}
	now := run.CompletedAt
	if a.Clock != nil {
		now = a.Clock.Now()
	}
	// Preserve real process output; split below the Logs per-event byte limit.
	for len(output) > 0 {
		n := min(len(output), 240<<10)
		chunk := output[:n]
		output = output[n:]
		_, rejected = a.Logs.PutLogEvents(ctx, &logsapi.PutLogEventsRequest{LogGroupName: new(logsapi.LogGroupName(group)), LogStreamName: new(logsapi.LogStreamName(stream)), LogEvents: logsapi.InputLogEvents{{Timestamp: new(logsapi.Timestamp(now.UnixMilli())), Message: new(logsapi.EventMessage(chunk))}}})
		if rejected != nil {
			return rejected
		}
	}
	return nil
}
