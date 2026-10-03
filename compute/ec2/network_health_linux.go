package ec2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func (a *guestAttachment) CheckHealth(ctx context.Context) (NetworkHealth, error) {
	var health NetworkHealth
	unlock, err := a.manager.lock(ctx)
	if err != nil {
		return health, err
	}
	defer unlock()
	if a.closed {
		return health, errors.New("guest network controller is closed")
	}
	links, err := a.manager.links(ctx, a.arn)
	if err != nil {
		return health, fmt.Errorf("inspect native guest attachment: %w", err)
	}
	for _, link := range links {
		if link.Name == a.tap {
			// A persistent TAP remains present after the VMM disconnects;
			// LOWER_UP observes the connected backend rather than mere existence.
			health.Attached = link.Master == a.bridge.Device && slices.Contains(link.Flags, "UP") && slices.Contains(link.Flags, "LOWER_UP")
			break
		}
	}
	if !health.Attached {
		return health, nil
	}

	output, err := a.manager.helper(ctx, a.arn, []string{"/bin/sh", "-ec", guestARPProbe}, []string{"LC_ALL=C", "BRIDGE=" + a.bridge.Device, "SOURCE=" + a.spec.Gateway.String(), "ADDRESS=" + a.spec.Address.String()})
	if err != nil {
		return health, fmt.Errorf("probe native guest ARP: %w", err)
	}
	// iputils can count an incoming ARP request as success and silently fail
	// to send. Its non-quiet output distinguishes replies and actual probes.
	sent := 0
	for line := range strings.SplitSeq(string(output), "\n") {
		if value, ok := strings.CutPrefix(line, "Sent "); ok {
			count, _, _ := strings.Cut(value, " probes (")
			sent, err = strconv.Atoi(count)
			if err != nil {
				return health, fmt.Errorf("decode native ARP probe count: %w", err)
			}
		}
		if strings.HasPrefix(line, "Unicast reply from ") || strings.HasPrefix(line, "Broadcast reply from ") {
			health.Reachable = true
		}
	}
	if sent == 0 {
		return health, errors.New("native ARP probe sent no packets")
	}
	return health, nil
}

// Preserve diagnostics separately: iputils also exits 1 for operational errors,
// not only an unanswered probe. No temporary files or writable rootfs are needed.
const guestARPProbe = `status=0
exec 3>&1
diagnostic=$(arping -c 2 -w 2 -I "$BRIDGE" -s "$SOURCE" "$ADDRESS" 2>&1 1>&3) || status=$?
if [ -n "$diagnostic" ]; then
    printf '%s\n' "$diagnostic" >&2
    exit 2
fi
case "$status" in
    0|1) exit 0 ;;
    *) exit "$status" ;;
esac`
