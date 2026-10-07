package ebs

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
)

func validControlVolumeID(id string) bool {
	if !strings.HasPrefix(id, "vol-") || len(id) != 12 && len(id) != 21 {
		return false
	}
	nonzero := false
	for i := 4; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		nonzero = nonzero || c != '0'
	}
	return nonzero
}

// controlVolumeID retains the DescribeVolumeAttribute/ModifyVolume ID dialect.
// DeleteVolume and ModifyVolumeAttribute use different native error shapes.
func controlVolumeID(id *api.VolumeId) error {
	if id == nil || *id == "" {
		text := "null"
		if id != nil {
			text = ""
		}
		return ec2Failure("MissingParameter", "Value ("+text+") for parameter volumeId is invalid. Parameter may not be null or empty.")
	}
	if !strings.HasPrefix(string(*id), "vol-") {
		return ec2Failure("InvalidParameterValue", "Value ("+string(*id)+") for parameter volumeId is invalid. Expected: 'vol-...'.")
	}
	if !validControlVolumeID(string(*id)) {
		return ec2Failure("InvalidVolumeID.Malformed", "Value ( "+string(*id)+" ) for parameter VOLUME is invalid. ")
	}
	return nil
}

// volumeControl resolves tags for authorization but defers native identifier and
// absence errors until after DryRun. The account-scoped lookup cannot grant access
// to a volume owned by another account.
func (s *Service) volumeControl(r Reader, action string, id *api.VolumeId, dry *api.Boolean) (VolumeRecord, error) {
	v, lookupErr := ownedVolume(r, value(id))
	if lookupErr != nil {
		var missing *awswire.Error
		if !errors.As(lookupErr, &missing) || missing.Code != "InvalidVolume.NotFound" {
			return VolumeRecord{}, lookupErr
		}
		resourceID := value(id)
		if !validControlVolumeID(resourceID) {
			resourceID = "*"
		}
		v.Key = VolumeKey{Scope: scopeFor(r.Context()), ID: resourceID}
	}
	if err := s.authorizeVolume(r.Context(), action, v, nil); err != nil {
		return VolumeRecord{}, err
	}
	if err := ec2DryRun(dry); err != nil {
		return VolumeRecord{}, err
	}
	if action == "ModifyVolumeAttribute" {
		if id == nil {
			return VolumeRecord{}, ec2Failure("MissingParameter", "volumeId")
		}
		if !validControlVolumeID(string(*id)) {
			return VolumeRecord{}, ec2Failure("InvalidVolumeID.Malformed", "The volume ID '"+string(*id)+"' is malformed")
		}
	} else if err := controlVolumeID(id); err != nil {
		if action == "EnableVolumeIO" {
			var malformed *awswire.Error
			if errors.As(err, &malformed) && malformed.Code == "InvalidVolumeID.Malformed" {
				return VolumeRecord{}, failure("InternalError", "An internal error has occurred", "", 500)
			}
		}
		return VolumeRecord{}, err
	}
	if lookupErr != nil {
		return VolumeRecord{}, lookupErr
	}
	if v.Status == api.VolumeStateDeleting {
		return VolumeRecord{}, volumeMissing(v.Key.ID)
	}
	if action != "DescribeVolumeAttribute" && action != "CreateSnapshot" {
		if err := volumeMutationFence(r.Context(), v); err != nil {
			return VolumeRecord{}, err
		}
	}
	return v, nil
}

func (s *Service) DescribeVolumeAttribute(ctx context.Context, in *api.DescribeVolumeAttributeRequest) (*api.DescribeVolumeAttributeResult, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out *api.DescribeVolumeAttributeResult
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.volumeControl(r, "DescribeVolumeAttribute", in.VolumeId, in.DryRun)
		if err != nil {
			return err
		}
		out = &api.DescribeVolumeAttributeResult{VolumeId: new(api.String(v.Key.ID))}
		switch value(in.Attribute) {
		case "autoEnableIO":
			out.AutoEnableIO = &api.AttributeBooleanValue{Value: new(api.Boolean(v.AutoEnableIO))}
		case "productCodes":
			out.ProductCodes = api.ProductCodeList{}
		case "":
			return ec2Failure("InvalidParameterCombination", "No attributes specified.")
		default:
			return ec2Failure("InvalidParameterValue", "Value ("+value(in.Attribute)+") for parameter attribute is invalid. Unknown attribute.")
		}
		return nil
	})
	return out, err
}

func (s *Service) ModifyVolumeAttribute(ctx context.Context, in *api.ModifyVolumeAttributeRequest) (*api.Unit, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.volumeControl(tx, "ModifyVolumeAttribute", in.VolumeId, in.DryRun)
		if err != nil {
			return err
		}
		if in.AutoEnableIO == nil || in.AutoEnableIO.Value == nil {
			return ec2Failure("InvalidParameterCombination", "No attributes specified.")
		}
		if enabled := bool(*in.AutoEnableIO.Value); enabled != v.AutoEnableIO {
			v.AutoEnableIO = enabled
			return tx.PutVolume(v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

func (s *Service) EnableVolumeIO(ctx context.Context, in *api.EnableVolumeIORequest) (*api.Unit, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.volumeControl(r, "EnableVolumeIO", in.VolumeId, in.DryRun)
		if err != nil {
			return err
		}
		// This disk owner has no impaired-I/O transition. Healthy volumes must
		// reject this action instead of pretending to repair nonexistent damage.
		return ec2Failure("IncorrectState", "Volume "+v.Key.ID+" already has IO enabled.")
	})
	return nil, err
}
