package organizations

import (
	"net/http"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/identitystore"
)

// Accounts, organizational units, policies and the delegation policy carry a private
// CloudFormation incarnation claim. Public tags are customer data: native
// TagResource/UntagResource can change them and they never establish ownership.
// Requests without trusted controller provenance remain ordinary IAM requests.

// cloudFormationClaim returns the trusted incarnation of a controller request.
func cloudFormationClaim(r *http.Request) string {
	return identitystore.CloudFormationOwner(r.Context())
}

// claimVisible lets an exact-incarnation observer see only its own rows.
func claimVisible(r *http.Request, stored string) bool {
	owner := cloudFormationClaim(r)
	return owner == "" || owner == stored
}

// claimMutation fences a controller mutation in the same revision that
// authorized it, so no tag or name check can race the change.
func claimMutation(r *http.Request, stored string) *awswire.Error {
	if !claimVisible(r, stored) {
		return failure("AccessDeniedException", "The resource is not owned by this CloudFormation incarnation.")
	}
	return nil
}

func accountClaimVisible(r *http.Request, a account) bool {
	return cloudFormationClaim(r) == "" || claimVisible(r, a.CloudFormationOwner) && a.CloudFormationRegion == awsctx.FromContext(r.Context()).Region
}

func accountClaimMutation(r *http.Request, a account) *awswire.Error {
	if !accountClaimVisible(r, a) {
		return failure("AccessDeniedException", "The account is not owned by this CloudFormation incarnation.")
	}
	return nil
}

// cloudFormationOwner reports the private claim of a claimable resource.
func (o *orgState) cloudFormationOwner(id string) (string, bool) {
	if o.resourcePolicy.ID != "" && id == o.resourcePolicy.ID {
		return o.resourcePolicy.CloudFormationOwner, true
	}
	if u, ok := o.units[id]; ok {
		return u.CloudFormationOwner, true
	}
	if p, ok := o.policies[id]; ok {
		return p.CloudFormationOwner, true
	}
	if a, ok := o.accounts[id]; ok {
		return a.CloudFormationOwner, true
	}
	return "", false
}

// claimTagTarget fences controller tag observation and mutation. Roots have no
// private incarnation claim, so controller requests cannot use them.
func (o *orgState) claimTagTarget(r *http.Request, id string, observe bool) *awswire.Error {
	if cloudFormationClaim(r) == "" {
		return nil
	}
	if a, ok := o.accounts[id]; ok {
		if accountClaimVisible(r, a) {
			return nil
		}
		return failure("AccessDeniedException", "The account is not owned by this CloudFormation incarnation.")
	}
	stored, claimable := o.cloudFormationOwner(id)
	if claimable && claimVisible(r, stored) {
		return nil
	}
	if observe {
		return failure("TargetNotFoundException", "The resource does not exist or does not support tags.")
	}
	return failure("AccessDeniedException", "The resource is not owned by this CloudFormation incarnation.")
}
