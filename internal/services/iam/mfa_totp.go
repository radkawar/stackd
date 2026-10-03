package iam

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/sts"
)

func invalidMFACode() *awswire.Error {
	return &awswire.Error{Code: "InvalidAuthenticationCode", Message: "The authentication code is invalid or the MFA device is out of sync.", StatusCode: 403}
}

func validMFACode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// totp implements RFC 6238's HMAC-SHA1 profile with six decimal digits and a
// thirty-second step, as used by AWS virtual MFA applications.
func totp(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, seed)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func matchCode(seed []byte, step int64, code string) bool {
	return subtle.ConstantTimeCompare([]byte(totp(seed, step)), []byte(code)) == 1
}

// synchronizeMFA accepts consecutive counters newer than the last accepted pair.
// Synchronization does not spend STS one-time codes. The generated IAM boundary
// owns code syntax; this transition owns device synchronization state.
func synchronizeMFA(device *MFADevice, userID, code1, code2 string, now time.Time) *awswire.Error {
	current := now.Unix() / 30
	binding := device.Binding.Value
	// Owned AWS captures accept second counters from -998 through +1000
	// steps around the device's adjusted time. Resynchronization retains that
	// adjustment as its search origin; adjacent outside counters are rejected.
	for delta := -998; delta <= 1000; delta++ {
		second := current + binding.SkewSteps + int64(delta)
		if device.LastPairStep != nil && second-1 <= *device.LastPairStep {
			continue
		}
		if matchCode([]byte(binding.Seed), second-1, code1) && matchCode([]byte(binding.Seed), second, code2) {
			device.LastPairStep = &second
			binding.SkewSteps = second - current
			binding.UserID = userID
			device.Binding.set(binding, now)
			device.pruneUsedCodes(now)
			return nil
		}
	}
	return invalidMFACode()
}

// Keep consumed counters for every binding STS can still observe. In particular,
// resynchronizing forward must not permit replay against the preceding window.
func (d *MFADevice) pruneUsedCodes(now time.Time) {
	d.Binding.advance(now)
	step := now.Unix() / 30
	d.UsedCodes = slices.DeleteFunc(d.UsedCodes, func(code MFAUsedCode) bool {
		relevant := func(binding MFABinding) bool {
			return binding.Seed == code.Seed && code.Step >= step+binding.SkewSteps-2
		}
		if relevant(d.Binding.VisibleValue) || relevant(d.Binding.Value) {
			return false
		}
		for _, change := range d.Binding.Pending {
			if relevant(change.Value) {
				return false
			}
		}
		return true
	})
}

// VerifyMFA verifies a current virtual-device code owned by the authenticated
// IAM user. STS uses the returned server timestamp for MFA session context.
func (s *Service) VerifyMFA(ctx context.Context, serial, code string) (time.Time, error) {
	// TODO: Comeback explain the remaining transient authentication after device replacement; complete the root, hardware and FIDO authentication audit.
	if !validMFACode(code) {
		return time.Time{}, invalidMFACode()
	}
	m := awsctx.FromContext(ctx)
	var now time.Time
	var rejection error
	scope := Scope{Partition: m.Partition, AccountID: m.AccountID}
	err := s.updateAt(ctx, func(tx WriteTx, instant time.Time) error {
		now = instant
		device, err := tx.MFADevice(scope, serial)
		if errors.Is(err, ErrRecordNotFound) {
			return sts.ErrMFAUnavailable
		}
		if err != nil {
			return err
		}
		binding, _ := device.Binding.valueAt(now)
		if binding.UserID == "" || binding.UserID != m.PrincipalID {
			return sts.ErrMFAUnavailable
		}
		users, err := tx.Users(scope)
		if err != nil {
			return err
		}
		live := false
		for _, u := range users {
			if u.UserId == m.PrincipalID && u.Arn == m.PrincipalARN {
				live = true
				break
			}
		}
		if !live {
			return sts.ErrMFAUnavailable
		}
		if !device.recordAttempt(now) {
			return sts.ErrMFAUnavailable
		}
		step := now.Unix()/30 + binding.SkewSteps
		for delta := int64(-2); delta <= 2; delta++ {
			candidate := step + delta
			if matchCode([]byte(binding.Seed), candidate, code) {
				used := MFAUsedCode{Seed: binding.Seed, Step: candidate}
				if slices.Contains(device.UsedCodes, used) {
					break
				}
				device.pruneUsedCodes(now)
				device.UsedCodes = append(device.UsedCodes, used)
				return tx.PutMFADevice(scope, device)
			}
		}
		// An invalid authentication is a committed domain outcome. The STS
		// caller returns its denial only after the authority commits this state.
		rejection = invalidMFACode()
		return tx.PutMFADevice(scope, device)
	})
	if err != nil {
		return time.Time{}, err
	}
	if rejection != nil {
		return time.Time{}, rejection
	}
	return now, nil
}
