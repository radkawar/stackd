package gateway

import (
	"context"
	"net/http"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// RegionAccess supplies Account Management eligibility for authenticated
// regional requests. Signature validity and token-format compatibility remain
// independent checks at their existing boundaries.
type RegionAccess interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

func (g *Gateway) checkRegion(r *http.Request, service *Service) *awswire.Error {
	if g.config.Regions == nil {
		return nil
	}
	switch service.SigningName {
	case "account", "iam", "organizations":
		return nil
	}
	m := awsctx.FromContext(r.Context())
	if m.Region == "aws-global" {
		return nil
	}
	enabled, err := g.config.Regions.RegionEnabled(r.Context(), m.AccountID, m.Region, g.config.Clock.Now().UTC())
	if err != nil {
		return &awswire.Error{Code: "InternalFailure", Message: "Unable to read account region eligibility.", StatusCode: 500}
	}
	if !enabled {
		return &awswire.Error{Code: "InvalidClientTokenId", Message: "The security token included in the request is invalid.", StatusCode: 403}
	}
	return nil
}
