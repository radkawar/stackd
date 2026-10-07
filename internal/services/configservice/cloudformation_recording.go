package configservice

// Channel admission fulfills the recorder owner's privately retained start intent.
// It does not borrow a different logical resource's claim or trust customer tags.
func (s *Service) startAdmittedRecorder(tx Transaction, r Recorder) error {
	if !r.StartOnCreate || r.CFNOwnership.Owner == "" || r.CFNOwnership.Token == "" || r.Recording {
		return nil
	}
	if err := s.authorizeResource(tx.Context(), "StartConfigurationRecorder", r.ARN); err != nil {
		return err
	}
	r.StartOnCreate = false
	r.Recording = true
	r.LastStart = s.clock.Now().UTC()
	r.LastStatusChange = r.LastStart
	r.LastStatus = "Success"
	r.LastErrorCode, r.LastErrorMessage = "", ""
	if err := tx.PutRecorder(r); err != nil {
		return err
	}
	return s.capture(tx, r, "")
}
