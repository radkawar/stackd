package organizations

import "testing"

func TestAccountAllocationSkipsKnownAndReservedIDs(t *testing.T) {
	const cursor = uint64(100000000000)
	known := allocatedAccountID(cursor + 1)
	pending := allocatedAccountID(cursor + 2)
	failed := allocatedAccountID(cursor + 3)
	record := PartitionRecord{
		AccountSequence: cursor,
		Accounts:        []AccountRecord{{ID: known}},
		Organizations: []OrganizationRecord{{
			Organization: OrganizationDetails{ID: "o-allocation"},
			Creations: []AccountCreationRecord{
				{ID: "car-pending", AccountID: pending, State: "IN_PROGRESS"},
				{ID: "car-failed", AccountID: failed, State: "FAILED"},
			},
		}},
	}
	state := &operationState{serviceState: decodeState(record, "aws", "731842905617")}
	id, sequence := state.nextAccountID()
	if sequence != cursor+4 || id != allocatedAccountID(cursor+4) {
		t.Fatalf("collision handling = %s/%d", id, sequence)
	}
	// Authorization must predict the same reservation without consuming it.
	if again, next := state.nextAccountID(); again != id || next != sequence || state.nextAccount != cursor {
		t.Fatalf("candidate lookup consumed allocation: %s/%d", again, next)
	}
	// A detached failed operation cannot alter the authoritative cursor.
	state.nextAccount = sequence
	reopened := &operationState{serviceState: decodeState(record, "aws", "731842905617")}
	if again, next := reopened.nextAccountID(); again != id || next != sequence {
		t.Fatalf("discarded operation changed allocation: %s/%d", again, next)
	}
	// Retaining a successful cursor advances deterministic allocation on reopen.
	reopened = &operationState{serviceState: decodeState(state.record(), "aws", "731842905617")}
	if again, next := reopened.nextAccountID(); again == id || next != sequence+1 {
		t.Fatalf("reopen reused allocated identity: %s/%d", again, next)
	}
}
