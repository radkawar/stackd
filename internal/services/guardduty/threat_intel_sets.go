package guardduty

import api "stackd/internal/awsapi/guardduty"

func registerThreatIntelSets(s *Service) {
	registerIPListMutation(s, "CreateThreatIntelSet", func(tx Transaction, in *api.CreateThreatIntelSetRequest) (*api.CreateThreatIntelSetResponse, *IPList, error) {
		v, pending, err := s.createIPList(tx, ipListCreate{Kind: ThreatIPList, DetectorID: value(in.DetectorId), Name: value(in.Name), Format: value(in.Format), Location: value(in.Location), ClientToken: value(in.ClientToken), Owner: in.ExpectedBucketOwner, Activate: in.Activate, Tags: in.Tags}, "CreateThreatIntelSet")
		if err != nil {
			return nil, nil, err
		}
		out := &api.CreateThreatIntelSetResponse{}
		text(&out.ThreatIntelSetId, v.ID)
		return out, pending, nil
	})
	register(s, "GetThreatIntelSet", func(tx Transaction, in *api.GetThreatIntelSetRequest) (*api.GetThreatIntelSetResponse, error) {
		v, err := s.loadIPList(tx, value(in.DetectorId), ThreatIPList, value(in.ThreatIntelSetId), "GetThreatIntelSet")
		if err != nil {
			return nil, err
		}
		out := &api.GetThreatIntelSetResponse{Tags: outputTags(v.Tags)}
		text(&out.Name, v.Name)
		text(&out.Format, v.Format)
		text(&out.Location, v.Location)
		text(&out.Status, v.Status)
		if v.ExpectedBucketOwner != "" {
			text(&out.ExpectedBucketOwner, v.ExpectedBucketOwner)
		}
		return out, nil
	})
	registerIPListMutation(s, "UpdateThreatIntelSet", func(tx Transaction, in *api.UpdateThreatIntelSetRequest) (*api.UpdateThreatIntelSetResponse, *IPList, error) {
		pending, err := s.updateIPList(tx, ipListUpdate{Kind: ThreatIPList, DetectorID: value(in.DetectorId), ID: value(in.ThreatIntelSetId), Name: in.Name, Location: in.Location, Owner: in.ExpectedBucketOwner, Activate: in.Activate}, "UpdateThreatIntelSet")
		return &api.UpdateThreatIntelSetResponse{}, pending, err
	})
	register(s, "DeleteThreatIntelSet", func(tx Transaction, in *api.DeleteThreatIntelSetRequest) (*api.DeleteThreatIntelSetResponse, error) {
		if err := s.deleteIPList(tx, value(in.DetectorId), ThreatIPList, value(in.ThreatIntelSetId), "DeleteThreatIntelSet"); err != nil {
			return nil, err
		}
		return &api.DeleteThreatIntelSetResponse{}, nil
	})
	register(s, "ListThreatIntelSets", func(tx Transaction, in *api.ListThreatIntelSetsRequest) (*api.ListThreatIntelSetsResponse, error) {
		ids, next, err := s.listIPLists(tx, value(in.DetectorId), ThreatIPList, "ListThreatIntelSets", in.MaxResults, value(in.NextToken))
		if err != nil {
			return nil, err
		}
		out := &api.ListThreatIntelSetsResponse{ThreatIntelSetIds: api.ThreatIntelSetIds(ids)}
		if next != "" {
			text(&out.NextToken, next)
		}
		return out, nil
	})
}
