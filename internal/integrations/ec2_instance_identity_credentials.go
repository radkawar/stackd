package integrations

import (
	"context"
	"errors"
	"strings"
	"time"

	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/ec2"
)

// EC2InstanceIdentityAuthority joins intrinsic issuance to the existing IAM
// credential transaction. No IAM role, profile or role-trust lookup is involved.
type EC2InstanceIdentityAuthority interface {
	WithSession(context.Context, func(context.Context, identity.Repository, time.Time) error) error
}

// EC2InstanceIdentityCredentials owns intrinsic delivery through IAM's retained
// credential repository. EC2 stores only the current credential's reference.
type EC2InstanceIdentityCredentials struct {
	IAM         EC2InstanceIdentityAuthority
	Credentials *identity.Store
}

var _ ec2.InstanceIdentities = (*EC2InstanceIdentityCredentials)(nil)

// TODO: Comeback capture long-lived intrinsic rotation, expiration and prior-key
// validity through profile changes, stop/start and termination. Six hours with
// replacement on expiry is local policy, not AWS's unpublished rotation or
// revocation policy.
const ec2IdentitySessionDuration = 6 * time.Hour

func (a *EC2InstanceIdentityCredentials) InstanceIdentityCredentials(ctx context.Context, instanceARN, previousID string, imdsv2 bool) (ec2.InstanceIdentityCredential, error) {
	metadata := awsctx.FromContext(ctx)
	prefix := "arn:" + metadata.Partition + ":ec2:" + metadata.Region + ":" + metadata.AccountID + ":instance/"
	instanceID, valid := strings.CutPrefix(instanceARN, prefix)
	if !valid || !strings.HasPrefix(instanceID, "i-") || strings.Contains(instanceID, "/") {
		return ec2.InstanceIdentityCredential{}, &awswire.Error{Code: "InvalidParameterValue", Message: "The instance must belong to the current account and region.", StatusCode: 400}
	}
	if a.IAM == nil || a.Credentials == nil {
		return ec2.InstanceIdentityCredential{}, &awswire.Error{Code: "InternalFailure", Message: "Intrinsic credential authority is not configured.", StatusCode: 500}
	}
	var delivered identity.Credential
	deliveryVersion := ec2RoleDelivery(imdsv2)
	err := a.IAM.WithSession(ctx, func(ctx context.Context, repository identity.Repository, now time.Time) error {
		if previousID != "" {
			err := repository.View(ctx, func(reader identity.Reader) error {
				record, err := reader.Get(previousID)
				if errors.Is(err, identity.ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				credential := record.Credential
				version := credential.SessionContext["ec2:roledelivery"]
				if record.Status == identity.Active && credential.Expiration.After(now) && credential.SessionType == identity.SessionTypeEC2InstanceIdentity && credential.AccountID == metadata.AccountID && credential.PrincipalARN == "arn:"+metadata.Partition+":sts::"+metadata.AccountID+":assumed-role/aws:ec2-instance/"+instanceID && len(version) == 1 && version[0] == deliveryVersion {
					delivered = credential
				}
				return nil
			})
			if err != nil {
				return err
			}
			if delivered.AccessKeyID != "" {
				return nil
			}
		}
		store := a.Credentials.WithRepositoryAt(repository, now)
		var err error
		delivered, err = store.IssueEC2InstanceIdentity(ctx, identity.EC2InstanceIdentitySpec{InstanceARN: instanceARN, RoleDelivery: deliveryVersion, Duration: ec2IdentitySessionDuration, RequestParentEventID: metadata.ParentEventID})
		return err
	})
	if err != nil {
		return ec2.InstanceIdentityCredential{}, err
	}
	return ec2.InstanceIdentityCredential{LastUpdated: delivered.CreateDate, Credentials: &stsapi.Credentials{
		AccessKeyId: new(stsapi.AccessKeyIdType(delivered.AccessKeyID)), SecretAccessKey: new(stsapi.AccessKeySecretType(delivered.SecretAccessKey)),
		SessionToken: new(stsapi.TokenType(delivered.SessionToken)), Expiration: &delivered.Expiration,
	}}, nil
}

func ec2RoleDelivery(imdsv2 bool) string {
	if imdsv2 {
		return "2.0"
	}
	return "1.0"
}
