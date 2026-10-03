package s3

import (
	"context"
	"errors"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3control"
	"stackd/internal/awswire"
)

// accessPointPublicAccess computes enforcement without mutating either stored
// configuration. Foreign bucket and access-point accounts remain independent.
func (s *Service) accessPointPublicAccess(reader Reader, point AccessPointRecord, bucket BucketRecord) (PublicAccessBlock, error) {
	effective, err := s.bucketPublicAccess(reader, bucket)
	if err != nil {
		return PublicAccessBlock{}, err
	}
	var account *PublicAccessBlock
	if point.Key.AccountID != bucket.AccountID {
		account, err = s.accountPublicAccess(reader, point.Key.Partition, point.Key.AccountID)
		if err != nil {
			return PublicAccessBlock{}, err
		}
	}
	for _, block := range [2]*PublicAccessBlock{&point.PublicAccess, account} {
		if block != nil {
			effective.BlockPublicACLs = effective.BlockPublicACLs || block.BlockPublicACLs
			effective.IgnorePublicACLs = effective.IgnorePublicACLs || block.IgnorePublicACLs
			effective.BlockPublicPolicy = effective.BlockPublicPolicy || block.BlockPublicPolicy
			effective.RestrictPublicBuckets = effective.RestrictPublicBuckets || block.RestrictPublicBuckets
		}
	}
	return effective, nil
}

func (p *Control) putAccessPointPolicy(ctx context.Context, in *api.PutAccessPointPolicyInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "PutAccessPointPolicy")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		point, err := p.controlAccessPoint(tx, value(in.AccountId), value(in.Name), false)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "PutAccessPointPolicy", nil, nil); err != nil {
			return err
		}
		document := value(in.Policy)
		if len(document) > 20*1024 {
			return failure("MalformedPolicy", "Policy exceeds the maximum allowed size.", 400)
		}
		bound, err := p.s.bindS3ResourcePolicy(tx.Context(), document)
		if err != nil {
			return err
		}
		public, err := accessPointPolicyPublic(document, point)
		if err != nil {
			return err
		}
		if public {
			block := point.PublicAccess.BlockPublicPolicy
			account, err := p.s.accountPublicAccess(tx, point.Key.Partition, point.Key.AccountID)
			if err != nil {
				return err
			}
			block = block || account != nil && account.BlockPublicPolicy
			// Bucket BlockPublicPolicy admission applies to its same-account
			// access points. Data enforcement still combines all four scopes.
			if point.BucketAccountID == point.Key.AccountID {
				bucket, err := tx.Bucket(point.Bucket)
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
				if err == nil {
					effective, err := p.s.accessPointPublicAccess(tx, point, bucket)
					if err != nil {
						return err
					}
					block = block || effective.BlockPublicPolicy
				}
			}
			if block {
				return denied()
			}
		}
		point.Policy = bound
		if err := tx.PutAccessPoint(point); err != nil {
			return err
		}
		return response.prepare(c, &api.PutAccessPointPolicyOutput{})
	})
	return response, wire
}

func (p *Control) getAccessPointPolicy(ctx context.Context, in *api.GetAccessPointPolicyInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "GetAccessPointPolicy")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		point, err := p.controlAccessPoint(tx, value(in.AccountId), value(in.Name), false)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "GetAccessPointPolicy", nil, nil); err != nil {
			return err
		}
		if point.Policy.Document == "" {
			return failure("NoSuchAccessPointPolicy", "The specified accesspoint policy does not exist", 404)
		}
		if p.s.binder == nil {
			return unsupported("Resource policy rendering is not configured.")
		}
		document, err := p.s.binder.RenderResourcePolicy(tx.Context(), point.Policy)
		if err != nil {
			return err
		}
		return response.prepare(c, &api.GetAccessPointPolicyOutput{Policy: new(api.Policy(document))})
	})
	return response, wire
}

func (p *Control) deleteAccessPointPolicy(ctx context.Context, in *api.DeleteAccessPointPolicyInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "DeleteAccessPointPolicy")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		point, err := p.controlAccessPoint(tx, value(in.AccountId), value(in.Name), false)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "DeleteAccessPointPolicy", nil, nil); err != nil {
			return err
		}
		point.Policy = authorization.BoundPolicy{}
		if err := tx.PutAccessPoint(point); err != nil {
			return err
		}
		return response.prepare(c, &api.DeleteAccessPointPolicyOutput{})
	})
	return response, wire
}

func (p *Control) getAccessPointPolicyStatus(ctx context.Context, in *api.GetAccessPointPolicyStatusInput) (*preparedResponse, *awswire.Error) {
	c := p.controlCall(ctx, "GetAccessPointPolicyStatus")
	response := &preparedResponse{}
	wire := p.s.execute(ctx, c, func(tx Transaction) error {
		point, err := p.controlAccessPoint(tx, value(in.AccountId), value(in.Name), false)
		if err != nil {
			return err
		}
		if err := p.authorizeAccessPoint(tx, point, "GetAccessPointPolicyStatus", nil, nil); err != nil {
			return err
		}
		if point.Policy.Document == "" {
			return failure("NoSuchAccessPointPolicy", "The specified accesspoint policy does not exist", 404)
		}
		public, err := accessPointPolicyPublic(point.Policy.Document, point)
		if err != nil {
			return err
		}
		return response.prepare(c, &api.GetAccessPointPolicyStatusOutput{PolicyStatus: &api.PolicyStatus{IsPublic: new(api.IsPublic(public))}})
	})
	return response, wire
}
