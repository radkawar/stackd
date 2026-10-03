package s3

import (
	"context"
	"net/http"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3control"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// TODO: Comeback capture native account-control write admission/regional propagation and Organizations S3 policy conformance.

func (p *Control) authorizeAccount(ctx context.Context, account, action string) *awswire.Error {
	if account != awsctx.FromContext(ctx).AccountID {
		return failure("AccessDenied", "Caller id does not match the account id in the endpoints.", http.StatusForbidden)
	}
	if wire := p.s.authorizer.Authorize(ctx, authorization.Request{
		Action: "s3:" + action, ResourceARN: "*", ResourceAccountID: account,
	}); wire != nil {
		return wire
	}
	if action == "PutAccountPublicAccessBlock" && p.s.accountPolicies != nil {
		_, managed, err := p.s.accountPolicies.S3PublicAccessBlock(ctx, awsctx.FromContext(ctx).Partition, account)
		if err != nil {
			return wireError(err)
		}
		if managed {
			return denied()
		}
	}
	return nil
}

func (p *Control) getPublicAccessBlock(ctx context.Context, in *api.GetPublicAccessBlockInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "GetPublicAccessBlock")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		account := value(in.AccountId)
		if wire := p.authorizeAccount(tx.Context(), account, "GetAccountPublicAccessBlock"); wire != nil {
			return wire
		}
		block, err := p.s.accountPublicAccess(tx, awsctx.FromContext(ctx).Partition, account)
		if err != nil {
			return err
		}
		if block == nil {
			wire := failure("NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found", http.StatusNotFound)
			wire.AccountID = account
			return wire
		}
		return response.prepare(c, &api.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &api.PublicAccessBlockConfiguration{
			BlockPublicAcls:       new(api.Setting(block.BlockPublicACLs)),
			IgnorePublicAcls:      new(api.Setting(block.IgnorePublicACLs)),
			BlockPublicPolicy:     new(api.Setting(block.BlockPublicPolicy)),
			RestrictPublicBuckets: new(api.Setting(block.RestrictPublicBuckets)),
		}})
	})
	return response, wire
}

func (p *Control) putPublicAccessBlock(ctx context.Context, in *api.PutPublicAccessBlockInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "PutPublicAccessBlock")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		account := value(in.AccountId)
		if wire := p.authorizeAccount(tx.Context(), account, "PutAccountPublicAccessBlock"); wire != nil {
			return wire
		}
		configuration := in.PublicAccessBlockConfiguration
		block := PublicAccessBlock{
			BlockPublicACLs:       publicAccessSetting(configuration.BlockPublicAcls),
			IgnorePublicACLs:      publicAccessSetting(configuration.IgnorePublicAcls),
			BlockPublicPolicy:     publicAccessSetting(configuration.BlockPublicPolicy),
			RestrictPublicBuckets: publicAccessSetting(configuration.RestrictPublicBuckets),
		}
		if err := tx.PutAccountPublicAccessBlock(awsctx.FromContext(ctx).Partition, account, block); err != nil {
			return err
		}
		return response.prepare(c, &api.PutPublicAccessBlockOutput{})
	})
	return response, wire
}

func (p *Control) deletePublicAccessBlock(ctx context.Context, in *api.DeletePublicAccessBlockInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "DeletePublicAccessBlock")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		account := value(in.AccountId)
		if wire := p.authorizeAccount(tx.Context(), account, "PutAccountPublicAccessBlock"); wire != nil {
			return wire
		}
		if err := tx.DeleteAccountPublicAccessBlock(awsctx.FromContext(ctx).Partition, account); err != nil {
			return err
		}
		return response.prepare(c, &api.DeletePublicAccessBlockOutput{})
	})
	return response, wire
}

func (s *Service) accountPublicAccess(reader Reader, partition, account string) (*PublicAccessBlock, error) {
	if s.accountPolicies != nil {
		enabled, managed, err := s.accountPolicies.S3PublicAccessBlock(reader.Context(), partition, account)
		if err != nil {
			return nil, err
		}
		if managed {
			return &PublicAccessBlock{
				BlockPublicACLs: enabled, IgnorePublicACLs: enabled,
				BlockPublicPolicy: enabled, RestrictPublicBuckets: enabled,
			}, nil
		}
	}
	return reader.AccountPublicAccessBlock(partition, account)
}
