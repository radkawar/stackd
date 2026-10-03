package guardduty

import api "stackd/internal/awsapi/guardduty"

func registerIPSets(s *Service) {
	registerIPListMutation(s, "CreateIPSet", func(tx Transaction, in *api.CreateIPSetRequest) (*api.CreateIPSetResponse, *IPList, error) {
		v, pending, err := s.createIPList(tx, ipListCreate{Kind: TrustedIPList, DetectorID: value(in.DetectorId), Name: value(in.Name), Format: value(in.Format), Location: value(in.Location), ClientToken: value(in.ClientToken), Owner: in.ExpectedBucketOwner, Activate: in.Activate, Tags: in.Tags}, "CreateIPSet")
		if err != nil {
			return nil, nil, err
		}
		out := &api.CreateIPSetResponse{}
		text(&out.IpSetId, v.ID)
		return out, pending, nil
	})
	register(s, "GetIPSet", func(tx Transaction, in *api.GetIPSetRequest) (*api.GetIPSetResponse, error) {
		v, err := s.loadIPList(tx, value(in.DetectorId), TrustedIPList, value(in.IpSetId), "GetIPSet")
		if err != nil {
			return nil, err
		}
		out := &api.GetIPSetResponse{Tags: outputTags(v.Tags)}
		text(&out.Name, v.Name)
		text(&out.Format, v.Format)
		text(&out.Location, v.Location)
		text(&out.Status, v.Status)
		if v.ExpectedBucketOwner != "" {
			text(&out.ExpectedBucketOwner, v.ExpectedBucketOwner)
		}
		return out, nil
	})
	registerIPListMutation(s, "UpdateIPSet", func(tx Transaction, in *api.UpdateIPSetRequest) (*api.UpdateIPSetResponse, *IPList, error) {
		pending, err := s.updateIPList(tx, ipListUpdate{Kind: TrustedIPList, DetectorID: value(in.DetectorId), ID: value(in.IpSetId), Name: in.Name, Location: in.Location, Owner: in.ExpectedBucketOwner, Activate: in.Activate}, "UpdateIPSet")
		return &api.UpdateIPSetResponse{}, pending, err
	})
	register(s, "DeleteIPSet", func(tx Transaction, in *api.DeleteIPSetRequest) (*api.DeleteIPSetResponse, error) {
		if err := s.deleteIPList(tx, value(in.DetectorId), TrustedIPList, value(in.IpSetId), "DeleteIPSet"); err != nil {
			return nil, err
		}
		return &api.DeleteIPSetResponse{}, nil
	})
	register(s, "ListIPSets", func(tx Transaction, in *api.ListIPSetsRequest) (*api.ListIPSetsResponse, error) {
		ids, next, err := s.listIPLists(tx, value(in.DetectorId), TrustedIPList, "ListIPSets", in.MaxResults, value(in.NextToken))
		if err != nil {
			return nil, err
		}
		out := &api.ListIPSetsResponse{IpSetIds: api.IpSetIds(ids)}
		if next != "" {
			text(&out.NextToken, next)
		}
		return out, nil
	})
}
