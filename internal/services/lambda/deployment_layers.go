package lambda

import (
	"context"
	"errors"

	runtime "stackd/compute/lambda"
	"stackd/internal/awswire"
)

// prepareLayers authorizes catalog reads before any external source access.
// Only explicit Layers input reaches this path; existing attachments remain
// usable after catalog deletion or source/policy changes.
func (s *Service) prepareLayers(ctx context.Context, function FunctionKey, arns []string) ([]LayerAttachment, *awswire.Error) {
	if len(arns) == 0 {
		return nil, nil
	}
	var records []LayerVersionRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var wire *awswire.Error
		records, wire = s.resolveLayers(r, function, arns)
		if wire != nil {
			return wire
		}
		return nil
	}); err != nil {
		return nil, wireError(err)
	}
	attachments := make([]LayerAttachment, 0, len(records))
	for _, record := range records {
		if record.Reference != nil {
			if s.codeSource == nil {
				return nil, unsupported("S3 deployment sources require configured S3 commands.")
			}
			if _, wire := s.codeSource.ReadReference(ctx, function.Scope, function.ARN(), *record.Reference); wire != nil {
				return nil, wire
			}
		}
		attachments = append(attachments, LayerAttachment{Key: record.Key, CodeSHA256: record.CodeSHA256, CodeSize: record.CodeSize, SigningProfileVersionARN: record.SigningProfileVersionARN, SigningJobARN: record.SigningJobARN})
	}
	return attachments, nil
}

// requireLayerCatalog owns attachment eligibility at the committing transaction.
// A prefetched immutable archive does not make a concurrently deleted catalog
// version attachable. Retaining or publishing an existing attachment skips this.
func requireLayerCatalog(r LayerReader, layers []LayerAttachment) *awswire.Error {
	for _, layer := range layers {
		if _, err := r.LayerVersion(layer.Key); errors.Is(err, ErrNotFound) {
			return unavailableLayer(layer.Key)
		} else if err != nil {
			return wireError(err)
		}
	}
	return nil
}

func unavailableLayer(key LayerVersionKey) *awswire.Error {
	return failure("InvalidParameterValueException", "Layer version "+key.ARN()+" does not exist.", 400)
}

func deploymentLayerCode(r Reader, layers []LayerAttachment) ([][]byte, error) {
	if len(layers) == 0 {
		return nil, nil
	}
	code := make([][]byte, 0, len(layers))
	for _, layer := range layers {
		archive, err := r.CodeArchive(CodeArchiveKey{Scope: layer.Key.Scope, SHA256: layer.CodeSHA256})
		if err != nil {
			return nil, err
		}
		code = append(code, archive.Code)
	}
	return code, nil
}

// validateDeploymentCode is the combined expanded quota boundary for both code
// and configuration admission. The runtime consumes the admitted archives.
func validateDeploymentCode(r Reader, code []byte, layers []LayerAttachment) *awswire.Error {
	if len(layers) == 0 {
		return nil
	}
	contents, err := deploymentLayerCode(r, layers)
	if err != nil {
		return wireError(err)
	}
	if err := runtime.ValidateDeploymentSize(code, contents); err != nil {
		return deploymentArchiveError(err)
	}
	return nil
}
