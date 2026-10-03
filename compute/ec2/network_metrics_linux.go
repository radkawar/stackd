package ec2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

func (i *nativeInstance) NetworkUsage(ctx context.Context) (NetworkUsage, error) {
	return i.attachment.NetworkUsage(ctx)
}

func (a *guestAttachment) NetworkUsage(ctx context.Context) (NetworkUsage, error) {
	unlock, err := a.manager.lock(ctx)
	if err != nil {
		return NetworkUsage{}, err
	}
	defer unlock()
	if a.closed {
		return NetworkUsage{}, errors.New("guest network controller is closed")
	}
	output, err := a.manager.helper(ctx, a.arn, []string{"ip", "-s", "-j", "link", "show", "dev", a.tap}, nil)
	if err != nil {
		return NetworkUsage{}, fmt.Errorf("observe native guest network counters: %w", err)
	}
	var links []struct {
		Index int `json:"ifindex"`
		Stats *struct {
			RX struct{ Bytes uint64 } `json:"rx"`
			TX struct{ Bytes uint64 } `json:"tx"`
		} `json:"stats64"`
	}
	if err := json.Unmarshal(output, &links); err != nil {
		return NetworkUsage{}, fmt.Errorf("decode native guest network counters: %w", err)
	}
	if len(links) != 1 || links[0].Index <= 0 || links[0].Stats == nil {
		return NetworkUsage{}, errors.New("native guest attachment has no 64-bit network counters")
	}
	// QEMU reads packets transmitted by the host TAP and writes packets that
	// the host TAP receives. Reverse the host-facing counters for AWS/EC2.
	return NetworkUsage{
		InterfaceIndex: links[0].Index,
		BytesIn:        links[0].Stats.TX.Bytes, BytesOut: links[0].Stats.RX.Bytes,
	}, nil
}
