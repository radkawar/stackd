package ram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awsctx"
	"strconv"
	"strings"
)

func page[T any](s *Service, r Reader, operation string, input any, rows []T, max *api.MaxResults, token *api.String) ([]T, *api.String, error) {
	limit := 500
	if max != nil {
		limit = int(*max)
		if limit < 1 || limit > 500 {
			return nil, nil, failure("InvalidMaxResultsException", "MaxResults must be between 1 and 500.")
		}
	}
	data, e := json.Marshal(input)
	if e != nil {
		return nil, nil, e
	}
	var filters map[string]json.RawMessage
	if e = json.Unmarshal(data, &filters); e != nil {
		return nil, nil, e
	}
	delete(filters, "nextToken")
	delete(filters, "maxResults")
	data, e = json.Marshal(filters)
	if e != nil {
		return nil, nil, e
	}
	m := awsctx.FromContext(r.Context())
	hash := sha256.Sum256([]byte(operation + "\x00" + m.Partition + "\x00" + m.Region + "\x00" + m.AccountID + "\x00" + m.PrincipalID + "\x00" + m.PrincipalARN + "\x00" + string(data)))
	fingerprint := hex.EncodeToString(hash[:])
	offset := 0
	if token != nil {
		raw, e := base64.RawURLEncoding.DecodeString(string(*token))
		if e != nil {
			return nil, nil, failure("InvalidNextTokenException", "Invalid pagination token.")
		}
		parts := strings.Split(string(raw), ".")
		if len(parts) != 3 || parts[0] != fingerprint {
			return nil, nil, failure("InvalidNextTokenException", "Pagination token does not match this query.")
		}
		mac := hmac.New(sha256.New, s.tokenKey[:])
		mac.Write([]byte(parts[0] + "." + parts[1]))
		signature, e := hex.DecodeString(parts[2])
		if e != nil || !hmac.Equal(signature, mac.Sum(nil)) {
			return nil, nil, failure("InvalidNextTokenException", "Invalid pagination token.")
		}
		offset, e = strconv.Atoi(parts[1])
		if e != nil || offset < 0 || offset > len(rows) {
			return nil, nil, failure("InvalidNextTokenException", "Pagination token is no longer valid.")
		}
	}
	end := min(offset+limit, len(rows))
	var next *api.String
	if end < len(rows) {
		payload := fingerprint + "." + strconv.Itoa(end)
		mac := hmac.New(sha256.New, s.tokenKey[:])
		mac.Write([]byte(payload))
		next = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(payload + "." + hex.EncodeToString(mac.Sum(nil))))))
	}
	return rows[offset:end], next, nil
}
func (s *Service) invitation(tx Reader, arn, op string) (Invitation, error) {
	v, e := tx.Invitation(arn)
	if e != nil {
		return v, failure("ResourceShareInvitationArnNotFoundException", "Invitation not found.")
	}
	sc := scopeFor(tx.Context())
	if v.Receiver != sc.AccountID || v.Partition != sc.Partition || v.Region != sc.Region {
		return Invitation{}, failure("ResourceShareInvitationArnNotFoundException", "Invitation not found.")
	}
	if e = s.authorize(tx, op, arn, nil); e != nil {
		return Invitation{}, e
	}
	v.Status = s.invitationStatus(v)
	return v, nil
}
func (s *Service) apiInvitation(r Reader, i Invitation) (api.ResourceShareInvitation, error) {
	out := api.ResourceShareInvitation{ResourceShareInvitationArn: new(api.String(i.ARN)), ResourceShareArn: new(api.String(i.ShareARN)), ResourceShareName: new(api.String(i.ShareName)), SenderAccountId: new(api.String(i.Sender)), ReceiverAccountId: new(api.String(i.Receiver)), InvitationTimestamp: &i.Created, Status: new(api.ResourceShareInvitationStatus(s.invitationStatus(i)))}
	sh, e := r.Share(i.ShareARN)
	if errors.Is(e, ErrNotFound) {
		return out, nil
	}
	if e != nil {
		return out, e
	}
	for _, a := range sh.Resources {
		out.ResourceShareAssociations = append(out.ResourceShareAssociations, apiAssociation(sh, a.ARN, "RESOURCE", a.Status, false, a.Created, a.Updated))
	}
	return out, nil
}
func (s *Service) respondInvitation(tx Transaction, arn, token, op string, input any, accept bool) (*api.String, *api.ResourceShareInvitation, error) {
	i, e := s.invitation(tx, arn, op)
	if e != nil {
		return nil, nil, e
	}
	// The owner-only native probe produced no invitation, so omission remains
	// uncalibrated here. Preserve this caller's existing generated-token path.
	if token == "" {
		token = identifier()
	}
	rec, replay, e := receipt(tx, op, new(api.String(token)), input)
	if e != nil {
		return nil, nil, e
	}
	if !replay {
		switch i.Status {
		case "EXPIRED":
			return nil, nil, failure("ResourceShareInvitationExpiredException", "The invitation has expired.")
		case "ACCEPTED":
			return nil, nil, failure("ResourceShareInvitationAlreadyAcceptedException", "The invitation is already accepted.")
		case "REJECTED":
			return nil, nil, failure("ResourceShareInvitationAlreadyRejectedException", "The invitation is already rejected.")
		}
		sh, e := tx.Share(i.ShareARN)
		if e != nil {
			return nil, nil, e
		}
		if sh.Status != "ACTIVE" {
			return nil, nil, failure("OperationNotPermittedException", "The resource share is no longer active.")
		}
		i.Status = "REJECTED"
		if accept {
			i.Status = "ACCEPTED"
		}
		i.Updated = s.clock.Now()
		for n := range sh.Principals {
			p := &sh.Principals[n]
			if p.InvitationARN == arn {
				p.Status = "DISASSOCIATED"
				if accept {
					p.Status = "ASSOCIATED"
				}
				if !accept {
					p.CloudFormationOwner = ""
				}
				p.Updated = i.Updated
			}
		}
		if e = tx.PutShare(sh); e != nil {
			return nil, nil, e
		}
		if e = tx.PutInvitation(i); e != nil {
			return nil, nil, e
		}
		rec.ARN = i.ARN
		if e = saveReceipt(tx, rec); e != nil {
			return nil, nil, e
		}
	}
	out, e := s.apiInvitation(tx, i)
	return new(api.String(rec.Token)), &out, e
}
func (s *Service) acceptResourceShareInvitation(tx Transaction, in *api.AcceptResourceShareInvitationRequest) (*api.AcceptResourceShareInvitationResponse, error) {
	token, out, e := s.respondInvitation(tx, value(in.ResourceShareInvitationArn), value(in.ClientToken), "AcceptResourceShareInvitation", in, true)
	return &api.AcceptResourceShareInvitationResponse{ClientToken: token, ResourceShareInvitation: out}, e
}
func (s *Service) rejectResourceShareInvitation(tx Transaction, in *api.RejectResourceShareInvitationRequest) (*api.RejectResourceShareInvitationResponse, error) {
	token, out, e := s.respondInvitation(tx, value(in.ResourceShareInvitationArn), value(in.ClientToken), "RejectResourceShareInvitation", in, false)
	return &api.RejectResourceShareInvitationResponse{ClientToken: token, ResourceShareInvitation: out}, e
}
func (s *Service) getResourceShareInvitations(tx Transaction, in *api.GetResourceShareInvitationsRequest) (*api.GetResourceShareInvitationsResponse, error) {
	if e := s.authorize(tx, "GetResourceShareInvitations", "", nil); e != nil {
		return nil, e
	}
	rows, e := tx.Invitations()
	if e != nil {
		return nil, e
	}
	sc := scopeFor(tx.Context())
	out := api.ResourceShareInvitationList{}
	for _, i := range rows {
		if i.Receiver != sc.AccountID || i.Partition != sc.Partition || i.Region != sc.Region || len(in.ResourceShareArns) > 0 && !slices.Contains(in.ResourceShareArns, api.String(i.ShareARN)) || len(in.ResourceShareInvitationArns) > 0 && !slices.Contains(in.ResourceShareInvitationArns, api.String(i.ARN)) {
			continue
		}
		v, e := s.apiInvitation(tx, i)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	out, next, e := page(s, tx, "GetResourceShareInvitations", in, out, in.MaxResults, in.NextToken)
	return &api.GetResourceShareInvitationsResponse{ResourceShareInvitations: out, NextToken: next}, e
}
func (s *Service) listPendingInvitationResources(tx Transaction, in *api.ListPendingInvitationResourcesRequest) (*api.ListPendingInvitationResourcesResponse, error) {
	i, e := s.invitation(tx, value(in.ResourceShareInvitationArn), "ListPendingInvitationResources")
	if e != nil {
		return nil, e
	}
	if i.Status != "PENDING" {
		return nil, failure("InvalidStateTransitionException", "Only pending invitations have pending resources.")
	}
	sh, e := tx.Share(i.ShareARN)
	if e != nil {
		return nil, e
	}
	out := api.ResourceList{}
	if value(in.ResourceRegionScope) != "GLOBAL" {
		for _, a := range sh.Resources {
			_, active, e := s.currentResource(tx, a)
			if e != nil {
				return nil, e
			}
			if active {
				out = append(out, apiResource(sh, a))
			}
		}
	}
	out, next, e := page(s, tx, "ListPendingInvitationResources", in, out, in.MaxResults, in.NextToken)
	return &api.ListPendingInvitationResourcesResponse{Resources: out, NextToken: next}, e
}
