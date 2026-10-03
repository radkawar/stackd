package ec2

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
)

func (s *Service) instanceProfileMetadata(ctx context.Context, instance InstanceRecord, item string, imdsv2 bool) ([]byte, string, int) {
	if s.instanceProfiles == nil {
		return nil, "", http.StatusNotFound
	}
	var association InstanceProfileAssociationRecord
	var delivered InstanceProfileCredential
	var deliveryError error
	err := s.repository.Update(ctx, func(tx Transaction) error {
		// The request's earlier instance read may precede a concurrent replace,
		// disassociate or termination. Resolve delivery under the owning lock.
		current, err := tx.Instance(instance.Key)
		if err != nil {
			return err
		}
		if current.Data.IamInstanceProfile == nil || instanceState(current) == "stopped" || instanceState(current) == "terminated" {
			return ErrNotFound
		}
		rows, err := tx.InstanceProfileAssociations(instance.Key.Scope)
		if err != nil {
			return err
		}
		found := false
		for _, row := range rows {
			if row.InstanceID == current.Key.ID && row.State != api.IamInstanceProfileAssociationStateDISASSOCIATED && row.ProfileARN == str(current.Data.IamInstanceProfile.Arn) && row.ProfileID == str(current.Data.IamInstanceProfile.Id) {
				association, found = row, true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		reference := association.Credentials.forVersion(imdsv2)
		delivered, deliveryError = s.instanceProfiles.InstanceProfileCredentials(tx.Context(), current.credentialOrigin(), *association.profile(), *reference, imdsv2)
		if deliveryError != nil {
			return nil
		}
		if delivered.Credentials != nil && str(delivered.Credentials.AccessKeyId) != *reference {
			*reference = str(delivered.Credentials.AccessKeyId)
			return tx.PutInstanceProfileAssociation(association)
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return nil, "", http.StatusNotFound
	}
	if err != nil {
		return nil, "", http.StatusInternalServerError
	}
	var rejected *awswire.Error
	if deliveryError != nil && !errors.As(deliveryError, &rejected) {
		return nil, "", http.StatusInternalServerError
	}
	if rejected != nil && rejected.Code != "AccessDenied" && rejected.Code != "InstanceProfileNotFound" {
		return nil, "", http.StatusInternalServerError
	}
	// A newly attached empty profile exposes no IAM subtree. A profile whose
	// delivered role was later removed instead retains the documented info
	// document after its existing credential reaches the refresh boundary.
	if delivered.RoleName == "" && association.Credentials == (InstanceCredentialReferences{}) && rejected == nil {
		return nil, "", http.StatusNotFound
	}
	item = strings.TrimSuffix(item, "/")
	if item == "iam" {
		if delivered.RoleName == "" {
			return metadataText("info")
		}
		return metadataText("info\nsecurity-credentials/")
	}
	if item == "iam/info" {
		if rejected != nil && rejected.Code == "InstanceProfileNotFound" {
			return metadataJSON(map[string]any{"Code": "InstanceProfileNotFound", "Message": "Instance profile not found.", "LastUpdated": association.Timestamp.UTC().Format(time.RFC3339)})
		}
		info := map[string]any{"Code": "Success", "InstanceProfileArn": association.ProfileARN, "InstanceProfileId": association.ProfileID, "LastUpdated": association.Timestamp.UTC().Format(time.RFC3339)}
		if delivered.RoleName == "" {
			info["Message"] = "Instance Profile does not contain a role."
		}
		return metadataJSON(info)
	}
	if delivered.RoleName == "" {
		return nil, "", http.StatusNotFound
	}
	if item == "iam/security-credentials" {
		return metadataText(delivered.RoleName)
	}
	if item != "iam/security-credentials/"+delivered.RoleName {
		return nil, "", http.StatusNotFound
	}
	if rejected != nil {
		return metadataJSON(map[string]any{"Code": "AssumeRoleUnauthorizedAccess", "Message": "EC2 cannot assume the role " + delivered.RoleName + ".  Please see documentation at https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_iam-ec2.html#troubleshoot_iam-ec2_errors-info-doc.", "LastUpdated": s.clock.Now().UTC().Format(time.RFC3339)})
	}
	credentials := delivered.Credentials
	if credentials == nil || credentials.AccessKeyId == nil || credentials.SecretAccessKey == nil || credentials.SessionToken == nil || credentials.Expiration == nil || !s.clock.Now().Before(time.Time(*credentials.Expiration)) {
		return nil, "", http.StatusInternalServerError
	}
	return metadataJSON(map[string]any{"Code": "Success", "Type": "AWS-HMAC", "AccessKeyId": str(credentials.AccessKeyId), "SecretAccessKey": str(credentials.SecretAccessKey), "Token": str(credentials.SessionToken), "Expiration": time.Time(*credentials.Expiration).UTC().Format(time.RFC3339), "LastUpdated": delivered.LastUpdated.UTC().Format(time.RFC3339)})
}
