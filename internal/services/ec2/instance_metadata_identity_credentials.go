package ec2

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Intrinsic identity is independent of the attached profile. EC2 retains only
// IAM's credential reference; signing material stays in the shared IAM store.
func (s *Service) instanceIntrinsicCredentialsMetadata(ctx context.Context, instance InstanceRecord, item string, imdsv2 bool) ([]byte, string, int) {
	if s.instanceIdentities == nil {
		return nil, "", http.StatusNotFound
	}
	item = strings.TrimSuffix(item, "/")
	switch item {
	case "identity-credentials":
		return metadataText("ec2/")
	case "identity-credentials/ec2":
		return metadataText("info\nsecurity-credentials/")
	case "identity-credentials/ec2/security-credentials":
		return metadataText("ec2-instance")
	case "identity-credentials/ec2/info":
		// Native info.LastUpdated differs from launch and credential times.
		// TODO: Comeback capture intrinsic-info publication/refresh timing.
		// Admission initializes this independently retained value from the
		// kernel clock; no relationship to AWS's opaque timestamp is claimed.
		body, _, status := metadataJSON(struct{ Code, LastUpdated, AccountId string }{
			Code: "Success", LastUpdated: instance.IdentityInfoLastUpdated.UTC().Format(time.RFC3339), AccountId: instance.Key.Scope.AccountID,
		})
		return body, "text/plain", status
	case "identity-credentials/ec2/security-credentials/ec2-instance":
	default:
		return nil, "", http.StatusNotFound
	}
	var delivered InstanceIdentityCredential
	err := s.repository.Update(ctx, func(tx Transaction) error {
		// Recheck under the owning transaction rather than minting from an
		// earlier read that may precede stop, termination or endpoint disable.
		current, err := tx.Instance(instance.Key)
		if err != nil {
			return err
		}
		if state := instanceState(current); state == "stopped" || state == "terminated" || current.Data.MetadataOptions == nil || str(current.Data.MetadataOptions.HttpEndpoint) != "enabled" {
			return ErrNotFound
		}
		reference := current.IdentityCredentials.forVersion(imdsv2)
		delivered, err = s.instanceIdentities.InstanceIdentityCredentials(tx.Context(), resourceARN(current.Key.Scope, "instance", current.Key.ID), *reference, imdsv2)
		if err != nil {
			return err
		}
		credentials := delivered.Credentials
		if credentials == nil || credentials.AccessKeyId == nil || credentials.SecretAccessKey == nil || credentials.SessionToken == nil || credentials.Expiration == nil || !s.clock.Now().Before(time.Time(*credentials.Expiration)) {
			return errors.New("intrinsic credential authority returned no live credential")
		}
		if id := str(credentials.AccessKeyId); id != *reference {
			*reference = id
			return tx.PutInstance(current)
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return nil, "", http.StatusNotFound
	}
	if err != nil {
		return nil, "", http.StatusInternalServerError
	}
	credentials := delivered.Credentials
	body, _, status := metadataJSON(struct{ Code, Type, AccessKeyId, SecretAccessKey, Token, Expiration, LastUpdated string }{
		Code: "Success", Type: "AWS-HMAC", AccessKeyId: str(credentials.AccessKeyId), SecretAccessKey: str(credentials.SecretAccessKey),
		Token: str(credentials.SessionToken), Expiration: time.Time(*credentials.Expiration).UTC().Format(time.RFC3339), LastUpdated: delivered.LastUpdated.UTC().Format(time.RFC3339),
	})
	return body, "text/plain", status
}
