package guardduty

import (
	"encoding/json"
	"errors"

	api "stackd/internal/awsapi/guardduty"
)

func registerFindings(s *Service) {
	register(s, "CreateSampleFindings", s.createSampleFindings)
	register(s, "GetFindings", s.getFindings)
	register(s, "ListFindings", s.listFindings)
	register(s, "ArchiveFindings", s.archiveFindings)
	register(s, "UnarchiveFindings", s.unarchiveFindings)
	register(s, "UpdateFindingsFeedback", s.updateFindingsFeedback)
	register(s, "GetFindingsStatistics", s.getFindingsStatistics)
}
func (s *Service) createSampleFindings(tx Transaction, in *api.CreateSampleFindingsInput) (*api.CreateSampleFindingsOutput, error) {
	detector, err := s.loadDetector(tx, value(in.DetectorId), "CreateSampleFindings")
	if err != nil {
		return nil, err
	}
	catalogue, err := samples()
	if err != nil {
		return nil, err
	}
	selected := catalogue.ordered
	if in.FindingTypes != nil {
		selected = nil
		seen := map[string]bool{}
		for _, kind := range in.FindingTypes {
			templates, ok := catalogue.byType[string(kind)]
			if !ok {
				return nil, invalid("The request contains an invalid finding type")
			}
			if !seen[string(kind)] {
				selected = append(selected, templates...)
				seen[string(kind)] = true
			}
		}
	}
	rows, err := tx.Findings(detector.Scope, detector.ID)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	byRevision := make(map[string]Finding, len(rows))
	for _, v := range rows {
		if !v.Archived && v.SampleRevision != "" && !findingExpired(v, now) {
			byRevision[v.SampleRevision] = v
		}
	}
	filters, err := tx.Filters(detector.Scope, detector.ID)
	if err != nil {
		return nil, err
	}
	for _, template := range selected {
		finding, exists := byRevision[template.revision]
		if !exists {
			finding = Finding{Scope: detector.Scope, DetectorID: detector.ID, ID: newID(), SampleType: value(template.finding.Type), SampleRevision: template.revision, Created: now}
		}
		finding.Updated = now
		finding.Count++
		if err := s.putOccurrence(tx, detector, finding, filters); err != nil {
			return nil, err
		}
	}
	return &api.CreateSampleFindingsOutput{}, nil
}
func (s *Service) getFindings(tx Transaction, in *api.GetFindingsInput) (*api.GetFindingsOutput, error) {
	detector, err := s.loadDetector(tx, value(in.DetectorId), "GetFindings")
	if err != nil {
		return nil, err
	}
	out := &api.GetFindingsOutput{Findings: api.Findings{}}
	seen := map[string]bool{}
	now := s.clock.Now()
	for _, id := range in.FindingIds {
		if seen[string(id)] {
			continue
		}
		seen[string(id)] = true
		row, err := tx.Finding(detector.Scope, detector.ID, string(id))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if findingExpired(row, now) {
			continue
		}
		finding, err := findingOutput(row)
		if err != nil {
			return nil, err
		}
		out.Findings = append(out.Findings, finding)
	}
	if err := sortFindings(out.Findings, in.SortCriteria); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) listFindings(tx Transaction, in *api.ListFindingsInput) (*api.ListFindingsOutput, error) {
	detector, err := s.loadDetector(tx, value(in.DetectorId), "ListFindings")
	if err != nil {
		return nil, err
	}
	if err := validateQueryCriteria(in.FindingCriteria); err != nil {
		return nil, err
	}
	kind := "findings/" + detector.ID
	if in.SortCriteria != nil {
		kind += "/" + value(in.SortCriteria.AttributeName) + "/" + value(in.SortCriteria.OrderBy)
	}
	limit, after, err := page(tx.Context(), kind, in.MaxResults, value(in.NextToken))
	if err != nil {
		return nil, err
	}
	var cursor api.Finding
	if after != "" {
		if err := json.Unmarshal([]byte(after), &cursor); err != nil || cursor.Id == nil {
			return nil, invalid("Invalid nextToken")
		}
	}
	rows, err := tx.Findings(detector.Scope, detector.ID)
	if err != nil {
		return nil, err
	}
	selected := make(api.Findings, 0, len(rows))
	now := s.clock.Now()
	for _, row := range rows {
		if findingExpired(row, now) {
			continue
		}
		finding, err := findingOutput(row)
		if err != nil {
			return nil, err
		}
		if matchesFinding(finding, in.FindingCriteria) {
			selected = append(selected, finding)
		}
	}
	if err := sortFindings(selected, in.SortCriteria); err != nil {
		return nil, err
	}
	out := &api.ListFindingsOutput{FindingIds: api.FindingIds{}}
	var last api.Finding
	for _, finding := range selected {
		if after != "" && compareFindings(finding, cursor, in.SortCriteria) <= 0 {
			continue
		}
		if len(out.FindingIds) == limit {
			key := api.Finding{AccountId: last.AccountId, Id: last.Id, Type: last.Type, Severity: last.Severity, Confidence: last.Confidence, CreatedAt: last.CreatedAt, UpdatedAt: last.UpdatedAt, Service: &api.Service{EventFirstSeen: last.Service.EventFirstSeen, EventLastSeen: last.Service.EventLastSeen}}
			data, err := json.Marshal(key)
			if err != nil {
				return nil, err
			}
			text(&out.NextToken, pageToken(tx.Context(), kind, string(data)))
			break
		}
		out.FindingIds = append(out.FindingIds, api.FindingId(value(finding.Id)))
		last = finding
	}
	return out, nil
}
func (s *Service) archiveFindings(tx Transaction, in *api.ArchiveFindingsInput) (*api.ArchiveFindingsOutput, error) {
	if err := s.setArchived(tx, value(in.DetectorId), in.FindingIds, true, "ArchiveFindings"); err != nil {
		return nil, err
	}
	return &api.ArchiveFindingsOutput{}, nil
}
func (s *Service) unarchiveFindings(tx Transaction, in *api.UnarchiveFindingsInput) (*api.UnarchiveFindingsOutput, error) {
	if err := s.setArchived(tx, value(in.DetectorId), in.FindingIds, false, "UnarchiveFindings"); err != nil {
		return nil, err
	}
	return &api.UnarchiveFindingsOutput{}, nil
}
func (s *Service) setArchived(tx Transaction, id string, ids api.FindingIds, archived bool, action string) error {
	d, err := s.loadDetector(tx, id, action)
	if err != nil {
		return err
	}
	now := s.clock.Now()
	for _, id := range ids {
		finding, err := tx.Finding(d.Scope, d.ID, string(id))
		if errors.Is(err, ErrNotFound) || err == nil && findingExpired(finding, now) {
			return invalid("The request contains an invalid finding ID")
		}
		if err != nil {
			return err
		}
		finding.Archived = archived
		if err := tx.PutFinding(finding); err != nil {
			return err
		}
		if err := s.queueFindingExports(tx, d, finding); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) updateFindingsFeedback(tx Transaction, in *api.UpdateFindingsFeedbackInput) (*api.UpdateFindingsFeedbackOutput, error) {
	d, err := s.loadDetector(tx, value(in.DetectorId), "UpdateFindingsFeedback")
	if err != nil {
		return nil, err
	}
	feedback := value(in.Feedback)
	if feedback != "USEFUL" && feedback != "NOT_USEFUL" {
		return nil, invalid("Invalid finding feedback")
	}
	now := s.clock.Now()
	for _, id := range in.FindingIds {
		finding, err := tx.Finding(d.Scope, d.ID, string(id))
		if errors.Is(err, ErrNotFound) || err == nil && findingExpired(finding, now) {
			continue
		}
		if err != nil {
			return nil, err
		}
		finding.Feedback = feedback
		if err := tx.PutFinding(finding); err != nil {
			return nil, err
		}
	}
	return &api.UpdateFindingsFeedbackOutput{}, nil
}
