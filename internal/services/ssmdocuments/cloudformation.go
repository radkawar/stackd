package ssmdocuments

import (
	"context"
	"maps"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type cloudFormationDocumentOwnerKey struct{}

// WithCloudFormationDocumentOwner binds an AWS::SSM::Document incarnation
// claim to ordinary, still-authorized document commands. It is internal
// command context, never wire input or a tag. Under a claim, CreateDocument
// records the claim on a new document or returns the document this claim
// already created, and every other command on the named document requires the
// stored claim in the same transaction as its effect.
func WithCloudFormationDocumentOwner(ctx context.Context, claim string) context.Context {
	return context.WithValue(ctx, cloudFormationDocumentOwnerKey{}, claim)
}

func cloudFormationDocumentOwner(ctx context.Context) (string, bool) {
	claim, ok := ctx.Value(cloudFormationDocumentOwnerKey{}).(string)
	return claim, ok && claim != ""
}

// checkDocumentOwner rejects a claimed command on a document the claim did not
// create, including a same-name recreation with copied tags.
func checkDocumentOwner(ctx context.Context, record Record) error {
	if claim, claimed := cloudFormationDocumentOwner(ctx); claimed && record.CloudFormationOwner != claim {
		return failure("AccessDeniedException", "The document belongs to a different CloudFormation resource incarnation.")
	}
	return nil
}

// loadClaimed loads the document a command addresses. Under a document claim
// it is visible only to the incarnation that created it; documents a command
// merely references, such as a required schema, use load.
func (s *Service) loadClaimed(r Reader, action, name string) (Record, error) {
	record, err := s.load(r, action, name)
	if err != nil {
		return record, err
	}
	if err := checkDocumentOwner(r.Context(), record); err != nil {
		return Record{}, err
	}
	return record, nil
}

// CloudFormationReplaceDocument implements UpdateMethod Replace without a
// destructive gap between native admission and retirement. It deliberately does
// not expose a second public SSM operation or bypass DeleteDocument/CreateDocument
// authority. A bound document claim fences the replaced incarnation privately,
// and the replacement keeps the replaced document's claim.
func (s *Service) CloudFormationReplaceDocument(ctx context.Context, in *api.CreateDocumentRequest) (*api.CreateDocumentResult, *awswire.Error) {
	if in == nil {
		return nil, failure("ValidationException", "Missing document replacement input.")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	ctx = awsctx.WithMetadata(ctx, metadata)
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var out *api.CreateDocumentResult
	action := "DeleteDocument"
	deletion := &api.DeleteDocumentRequest{Name: in.Name}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		current, err := s.load(tx, "DeleteDocument", value(in.Name))
		if err != nil {
			return err
		}
		if err := checkDocumentOwner(tx.Context(), current); err != nil {
			return err
		}
		action = "CreateDocument"
		next, version, err := s.admitDocument(tx, in, true)
		if err != nil {
			return err
		}
		next.CloudFormationOwner = current.CloudFormationOwner
		old, err := selectVersion(tx, current, "$DEFAULT", "")
		if err != nil {
			return err
		}
		// A replay, or rollback of a rejected replacement, must not erase the
		// untouched document's version history by replacing it with itself.
		if sameDocumentReplacement(current, old, next, version) {
			desc, err := description(current, old)
			out = &api.CreateDocumentResult{DocumentDescription: desc}
			return err
		}
		action = "DeleteDocument"
		if current.Type == "ApplicationConfigurationSchema" {
			deletion.Force = new(api.Boolean(true))
		}
		deleted, err := deleteLoadedDocument(tx, current, deletion)
		if err != nil {
			return err
		}
		action = "CreateDocument"
		out, err = persistDocument(tx, next, version)
		if err != nil {
			return err
		}
		// Both real native effects and their API observations commit together.
		// A failure at either audit boundary restores bytes, versions and shares.
		deleteContext, err := apievents.Reserve(tx.Context())
		if err != nil {
			return err
		}
		deleteMetadata := awsctx.FromContext(deleteContext)
		deleteMetadata.RequestID = uuid.NewString()
		deleteContext = awsctx.WithMetadata(deleteContext, deleteMetadata)
		if err = s.record(deleteContext, "DeleteDocument", deletion, deleted, nil, ""); err != nil {
			return err
		}
		return s.recordSuccess(tx, "CreateDocument", in, out)
	})
	if err == nil {
		s.jobs.Wake()
		return out, nil
	}
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	var rejectedInput any = in
	if action == "DeleteDocument" {
		rejectedInput = deletion
	}
	if err = s.record(completion, action, rejectedInput, nil, rejected, ""); err != nil {
		return nil, wireError(err)
	}
	return nil, rejected
}

func sameDocumentReplacement(a Record, av Version, b Record, bv Version) bool {
	return a.Key == b.Key && a.Type == b.Type && a.SchemaName == b.SchemaName && a.SchemaDocumentID == b.SchemaDocumentID && a.SchemaVersion == b.SchemaVersion && maps.Equal(a.Tags, b.Tags) && av.Content == bv.Content && av.Format == bv.Format && av.VersionName == bv.VersionName && av.DisplayName == bv.DisplayName && av.TargetType == bv.TargetType
}
