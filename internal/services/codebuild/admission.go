package codebuild

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awsctx"
)

// buildAdmission identifies an admitted request, separately from its runtime inputs.
// RetrySourceID also separates RetryBuild's token namespace from StartBuild.
type buildAdmission struct {
	Token, RequestHash, RetrySourceID string
}

func (s *Service) enqueueBuild(ctx context.Context, tx Transaction, project *ProjectRecord, p *api.Project, pipeline PipelineBuild, admission buildAdmission) (*BuildRecord, error) {
	key, now := project.Key, s.clock.Now()
	id := key.Name + ":" + uuid.NewString()
	bkey := BuildKey{key.Scope, id}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	project.BuildNumber++
	var sourceVersion *api.NonEmptyString
	if version := value(p.SourceVersion); version != "" {
		sourceVersion = new(api.NonEmptyString(version))
	}
	initiator := awsctx.FromContext(ctx).PrincipalARN
	if strings.Contains(initiator, ":user/") {
		initiator = initiator[strings.LastIndexByte(initiator, '/')+1:]
	} else if _, role, ok := strings.Cut(initiator, ":assumed-role/"); ok {
		initiator = role
	}
	data := api.Build{
		Arn: new(api.NonEmptyString(bkey.ARN())), Id: new(api.NonEmptyString(id)), ProjectName: new(api.NonEmptyString(key.Name)),
		BuildNumber: new(api.WrapperLong(project.BuildNumber)), BuildStatus: new(api.StatusType("IN_PROGRESS")), BuildComplete: new(api.Boolean(false)),
		CurrentPhase: new(api.String("QUEUED")), StartTime: &now, Source: p.Source, SourceVersion: sourceVersion,
		Environment: p.Environment, ServiceRole: p.ServiceRole, Cache: p.Cache, EncryptionKey: p.EncryptionKey,
		TimeoutInMinutes: new(api.WrapperInt(*p.TimeoutInMinutes)), QueuedTimeoutInMinutes: new(api.WrapperInt(*p.QueuedTimeoutInMinutes)),
		Initiator: new(api.String(initiator)),
		Phases: api.BuildPhases{
			{PhaseType: new(api.BuildPhaseType("SUBMITTED")), PhaseStatus: new(api.StatusType("SUCCEEDED")), StartTime: &now, EndTime: &now, DurationInSeconds: new(api.WrapperLong(0))},
			{PhaseType: new(api.BuildPhaseType("QUEUED")), StartTime: &now},
		},
		SecondarySources: p.SecondarySources, SecondarySourceVersions: p.SecondarySourceVersions,
	}
	record := BuildRecord{
		Key: bkey, Data: data, Artifacts: *p.Artifacts, Logs: *p.LogsConfig, AcceptedEventID: apievents.EventID(ctx),
		IdempotencyToken: admission.Token, RequestHash: admission.RequestHash, RetrySourceID: admission.RetrySourceID,
		QueuedDeadline: now.Add(time.Duration(*p.QueuedTimeoutInMinutes) * time.Minute), CredentialToken: hex.EncodeToString(token[:]),
		SecondaryArtifacts: p.SecondaryArtifacts, PipelineInputs: pipeline.Inputs, PipelineOutputs: pipeline.Outputs,
	}
	if value(p.Artifacts.Type) == "CODEPIPELINE" && value(p.Artifacts.Location) != "" && len(pipeline.Outputs) <= 1 {
		// Native reports the configured destination before bytes exist. Checksums
		// are populated only after the actual artifact upload succeeds.
		record.Data.Artifacts = &api.BuildArtifacts{Location: p.Artifacts.Location, EncryptionDisabled: new(api.WrapperBoolean(false))}
	}
	if pipeline.PipelineName != "" {
		record.PipelineActionID, _ = ctx.Value(pipelineActionKey{}).(string)
		record.Data.Initiator = new(api.String("codepipeline/" + pipeline.PipelineName))
		if revision := pipeline.Inputs[0].RevisionID; revision != "" {
			record.Data.ResolvedSourceVersion = new(api.NonEmptyString(revision))
		}
	}
	if p.Environment.Fleet != nil {
		record.FleetARN = value(p.Environment.Fleet.FleetArn)
	}
	if err := tx.PutProject(*project); err != nil {
		return nil, err
	}
	if err := s.putBuild(ctx, tx, record, true); err != nil {
		return nil, err
	}
	return &record, nil
}
