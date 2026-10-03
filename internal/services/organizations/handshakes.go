package organizations

import (
	"net/http"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerHandshakeOperations() {
	register(s, "EnableAllFeatures", (*operationState).enableAllFeatures)
	register(s, "InviteAccountToOrganization", (*operationState).inviteAccount)
	register(s, "AcceptHandshake", (*operationState).acceptHandshake)
	register(s, "DescribeHandshake", func(s *operationState, r *http.Request, in *api.DescribeHandshakeInput) (*api.DescribeHandshakeOutput, *awswire.Error) {
		i, err := s.handshake(inputString(in.HandshakeId))
		if err != nil {
			return nil, err
		}
		return &api.DescribeHandshakeOutput{Handshake: i.api(s.partition)}, nil
	})
	register(s, "CancelHandshake", func(s *operationState, r *http.Request, in *api.CancelHandshakeInput) (*api.CancelHandshakeOutput, *awswire.Error) {
		i, err := s.transitionHandshake(r, inputString(in.HandshakeId), "CANCELED")
		if err != nil {
			return nil, err
		}
		return &api.CancelHandshakeOutput{Handshake: i.api(s.partition)}, nil
	})
	register(s, "DeclineHandshake", func(s *operationState, r *http.Request, in *api.DeclineHandshakeInput) (*api.DeclineHandshakeOutput, *awswire.Error) {
		i, err := s.transitionHandshake(r, inputString(in.HandshakeId), "DECLINED")
		if err != nil {
			return nil, err
		}
		return &api.DeclineHandshakeOutput{Handshake: i.api(s.partition)}, nil
	})
	register(s, "ListHandshakesForAccount", func(s *operationState, r *http.Request, in *api.ListHandshakesForAccountInput) (*api.ListHandshakesForAccountOutput, *awswire.Error) {
		items, next, err := s.listHandshakes(in, in.Filter, "")
		return &api.ListHandshakesForAccountOutput{Handshakes: items, NextToken: nextToken(next)}, err
	})
	register(s, "ListHandshakesForOrganization", func(s *operationState, r *http.Request, in *api.ListHandshakesForOrganizationInput) (*api.ListHandshakesForOrganizationOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		items, next, err := s.listHandshakes(in, in.Filter, o.organization.ID)
		return &api.ListHandshakesForOrganizationOutput{Handshakes: items, NextToken: nextToken(next)}, err
	})
}

func (s *operationState) handshake(id string) (HandshakeRecord, *awswire.Error) {
	i, ok := s.handshakes[id]
	if ok {
		i, ok = s.observeHandshake(i)
	}
	if !ok {
		return HandshakeRecord{}, failure("HandshakeNotFoundException", "The handshake does not exist.")
	}
	return i, nil
}

func handshakeTransition(i HandshakeRecord, state string) *awswire.Error {
	if i.State == state {
		return failure("HandshakeAlreadyInStateException", "The handshake is already in the requested state.")
	}
	if i.State != "OPEN" && !(i.State == "REQUESTED" && state == "CANCELED") {
		return failure("InvalidHandshakeTransitionException", "The handshake cannot transition from its current state.")
	}
	return nil
}

func (s *operationState) transitionHandshake(r *http.Request, id, state string) (HandshakeRecord, *awswire.Error) {
	i, err := s.handshake(id)
	if err != nil {
		return i, err
	}
	if err = handshakeTransition(i, state); err != nil {
		return i, err
	}
	i = s.finishHandshake(r, i, state)
	if i.Action == "ENABLE_ALL_FEATURES" {
		s.cancelFeatureChildren(i, awsctx.FromContext(r.Context()))
	}
	return i, nil
}

// finishHandshake publishes a transition after the operation has checked the
// source state and its membership constraints.
func (s *operationState) finishHandshake(r *http.Request, i HandshakeRecord, state string) HandshakeRecord {
	i.State = state
	if !i.pending() {
		i.TerminalAt = s.instant
	}
	if state == "ACCEPTED" && i.Action == "INVITE" {
		i.TargetAccountID = awsctx.FromContext(r.Context()).AccountID
	}
	s.handshakes[i.ID] = i
	s.recordHandshake(i, awsctx.FromContext(r.Context()))
	return i
}

func (s *operationState) listHandshakes(in paginationInput, filter *api.HandshakeFilter, orgID string) (api.Handshakes, string, *awswire.Error) {
	action, parent := "", ""
	if filter != nil {
		action, parent = inputString(filter.ActionType), inputString(filter.ParentHandshakeId)
		if filter.ActionType != nil && filter.ParentHandshakeId != nil {
			return nil, "", failure("InvalidInputException", "MAX_LIMIT_EXCEEDED_FILTER: Specify only one handshake filter.")
		}
	}
	items := make([]HandshakeRecord, 0)
	for _, stored := range s.handshakes {
		i, visible := s.observeHandshake(stored)
		if !visible || action != "" && action != i.Action || parent != "" && parent != i.ParentID {
			continue
		}
		if orgID != "" && i.OrganizationID == orgID || orgID == "" && s.invitationRecipient(i, s.caller) {
			items = append(items, i)
		}
	}
	items, next, err := paginate(s, items, in, "handshakes/"+orgID+"/"+action+"/"+parent, func(i HandshakeRecord) string { return i.ID })
	out := make(api.Handshakes, len(items))
	for n, i := range items {
		out[n] = *i.api(s.partition)
	}
	return out, next, err
}
