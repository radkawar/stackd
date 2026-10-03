package eventbridge

import "time"

func connectionAPIDestinationActive(connection ConnectionRecord) bool {
	return connection.State == "AUTHORIZED" || connection.State == "DEAUTHORIZING"
}

// Authorization transitions change destination state. Deleting an active
// Connection also clears its reference; already-inactive references are retained.
// Publish the modification and invocation fence in the same transaction.
func (s *Service) updateConnectionAPIDestinations(tx Transaction, previous, current ConnectionRecord) error {
	if connectionAPIDestinationActive(previous) == connectionAPIDestinationActive(current) {
		return nil
	}
	rows, err := tx.APIDestinations(previous.Key.Scope)
	if err != nil {
		return err
	}
	arn := previous.ARN()
	now := s.clock.Now().Truncate(time.Second)
	for _, destination := range rows {
		if destination.ConnectionARN != arn {
			continue
		}
		if current.State == "DELETING" {
			destination.ConnectionARN = ""
		}
		destination.Modified = now
		destination.Version++
		if err := tx.PutAPIDestination(destination); err != nil {
			return err
		}
	}
	return nil
}
