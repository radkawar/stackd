package ec2

import (
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func networkCreation(tx Reader, scope Scope, action string, token *api.String, vpcID string, tags api.TagList) (NetworkCreationRecord, error) {
	admitted := NetworkCreationRecord{Key: NetworkCreationKey{Scope: scope, Action: action, Token: str(token)}, VPCID: vpcID, Tags: tags}
	if token == nil {
		return admitted, nil
	}
	if len(*token) == 0 {
		return NetworkCreationRecord{}, failure("InvalidParameterValue", "ClientToken must contain between 1 and 64 ASCII characters.")
	}
	for _, character := range *token {
		if character > 127 {
			return NetworkCreationRecord{}, failure("InvalidParameterValue", "ClientToken must contain ASCII characters.")
		}
		if character < 32 && character != '\t' && character != '\n' && character != '\r' {
			return NetworkCreationRecord{}, failure("InvalidCharacter", "ClientToken contains an invalid XML character.")
		}
	}
	// EC2 trims surrounding whitespace, and a whitespace-only token disables
	// idempotency. A nonblank token's limit still applies to its original length.
	admitted.Key.Token = strings.TrimSpace(string(*token))
	if admitted.Key.Token == "" {
		return admitted, nil
	}
	if len(*token) > 64 {
		return NetworkCreationRecord{}, failure("InvalidParameterValue", "ClientToken must contain between 1 and 64 ASCII characters.")
	}
	prior, err := tx.NetworkCreation(admitted.Key)
	if errors.Is(err, ErrNotFound) {
		return admitted, nil
	}
	if err != nil {
		return NetworkCreationRecord{}, err
	}
	// TODO: Comeback establish native token retention bounds and resolve the
	// captured case-only InternalError anomaly; keys follow AWS's documented
	// case-sensitive contract and successful outcomes remain retained meanwhile.
	if prior.VPCID != vpcID || !slices.EqualFunc(prior.Tags, tags, func(a, b api.Tag) bool {
		return str(a.Key) == str(b.Key) && str(a.Value) == str(b.Value)
	}) {
		return NetworkCreationRecord{}, creationMismatch()
	}
	return prior, nil
}

func (r *NetworkCreationRecord) clientToken() *api.String {
	if r.Key.Token == "" {
		return nil
	}
	return new(api.String(r.Key.Token))
}

func creationMismatch() error {
	return failure("IdempotentParameterMismatch", "ClientToken was previously used with different parameters or a resource that has been deleted.")
}
