package ports

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
)

func TestParseAndValidate(t *testing.T) {
	for _, tc := range []struct {
		text string
		want Range
	}{{"", Range{}}, {"1-65535", Range{1, 65535}}, {"65535-65535", Range{65535, 65535}}, {"24000-24002", Range{24000, 24002}}} {
		got, err := Parse(tc.text)
		if err != nil || got != tc.want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", tc.text, got, err, tc.want)
		}
	}
	for _, text := range []string{"0-0", "0-1", "1-0", "2-1", "65536-65536", "-1-2", "+1-2", "1", "1-2-3", "1-", "-2", " 1-2", "1-2 ", "one-two"} {
		if _, err := Parse(text); err == nil {
			t.Errorf("Parse(%q) accepted invalid range", text)
		}
	}
	for _, r := range []Range{{0, 1}, {1, 0}, {2, 1}} {
		if err := r.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted invalid bounds", r)
		}
	}
}

// Claim an actually available contiguous interval rather than assuming a fixed
// test port is free on the developer's machine. Keep all claims until returned.
func testRange(t *testing.T, count int) (Range, []net.Listener) {
	t.Helper()
	for range 100 {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		base := first.Addr().(*net.TCPAddr).Port
		held := []net.Listener{first}
		if base+count-1 <= 65535 {
			for offset := 1; offset < count; offset++ {
				listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(base+offset)))
				if err != nil {
					break
				}
				held = append(held, listener)
			}
			if len(held) == count {
				t.Cleanup(func() {
					for _, listener := range held {
						listener.Close()
					}
				})
				return Range{uint16(base), uint16(base + count - 1)}, held
			}
		}
		for _, listener := range held {
			listener.Close()
		}
	}
	t.Fatal("could not reserve a contiguous local test interval")
	return Range{}, nil
}

func TestInclusiveDeterministicReservationAndExhaustion(t *testing.T) {
	r, held := testRange(t, 3)
	if listener, err := r.Listen(t.Context(), "127.0.0.1", 0); !errors.Is(err, ErrExhausted) {
		if listener != nil {
			listener.Close()
		}
		t.Fatalf("full pool: %v", err)
	}
	if err := held[2].Close(); err != nil {
		t.Fatal(err)
	}
	last, err := r.Listen(t.Context(), "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer last.Close()
	if got := last.Addr().(*net.TCPAddr).Port; got != int(r.Last) {
		t.Fatalf("inclusive final bound = %d; want %d", got, r.Last)
	}
	if err := held[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := held[1].Close(); err != nil {
		t.Fatal(err)
	}
	first, err := r.Listen(t.Context(), "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if got := first.Addr().(*net.TCPAddr).Port; got != int(r.First) {
		t.Fatalf("deterministic first available = %d; want %d", got, r.First)
	}
	competing, err := net.Listen("tcp4", first.Addr().String())
	if err == nil {
		competing.Close()
		t.Fatal("reservation did not hold a real exclusive socket")
	}
}

func TestExplicitPortRemainsExactOutsideFullPool(t *testing.T) {
	r, _ := testRange(t, 1)
	outside, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requested := uint16(outside.Addr().(*net.TCPAddr).Port)
	if listener, err := r.Listen(t.Context(), "127.0.0.1", requested); err == nil || errors.Is(err, ErrExhausted) {
		if listener != nil {
			listener.Close()
		}
		outside.Close()
		t.Fatalf("occupied explicit port silently substituted or treated as automatic: %v", err)
	}
	if err := outside.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := r.Listen(t.Context(), "127.0.0.1", requested)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if got := listener.Addr().(*net.TCPAddr).Port; got != int(requested) {
		t.Fatalf("explicit port moved to %d; want %d", got, requested)
	}
}

func TestConcurrentPoolClaimsAreDistinct(t *testing.T) {
	const count = 12
	r, placeholders := testRange(t, count)
	for _, listener := range placeholders {
		listener.Close()
	}
	start := make(chan struct{})
	listeners := make([]net.Listener, count)
	errorsByClaim := make([]error, count)
	var group sync.WaitGroup
	for claim := range count {
		group.Go(func() {
			<-start
			listeners[claim], errorsByClaim[claim] = r.Listen(t.Context(), "127.0.0.1", 0)
		})
	}
	close(start)
	group.Wait()
	defer func() {
		for _, listener := range listeners {
			if listener != nil {
				listener.Close()
			}
		}
	}()
	seen := make(map[int]bool, count)
	for claim, listener := range listeners {
		if errorsByClaim[claim] != nil {
			t.Fatalf("claim %d: %v", claim, errorsByClaim[claim])
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if port < int(r.First) || port > int(r.Last) || seen[port] {
			t.Fatalf("duplicate/out-of-pool held port %d", port)
		}
		seen[port] = true
	}
	if listener, err := r.Listen(t.Context(), "127.0.0.1", 0); !errors.Is(err, ErrExhausted) {
		if listener != nil {
			listener.Close()
		}
		t.Fatalf("concurrent pool exhaustion: %v", err)
	}
}

func TestCancellationAndEphemeralDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, r := range []Range{{}, {30000, 30001}} {
		if listener, err := r.Listen(ctx, "127.0.0.1", 0); !errors.Is(err, context.Canceled) {
			if listener != nil {
				listener.Close()
			}
			t.Fatalf("canceled allocation: %v", err)
		}
	}
	listener, err := (Range{}).Listen(t.Context(), "127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if listener.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("ephemeral reservation has zero port")
	}
	if listener, err := (Range{30000, 30001}).Listen(t.Context(), "invalid:host", 0); err == nil || errors.Is(err, ErrExhausted) {
		if listener != nil {
			listener.Close()
		}
		t.Fatalf("non-occupancy bind error hidden as exhaustion: %v", err)
	}
}

func TestMaximumPortDoesNotWrap(t *testing.T) {
	occupied, err := net.Listen("tcp4", "127.0.0.1:65535")
	if err == nil {
		defer occupied.Close()
	}
	listener, err := (Range{65535, 65535}).Listen(t.Context(), "127.0.0.1", 0)
	if listener != nil {
		listener.Close()
		t.Fatal("allocated beyond occupied maximum port")
	}
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("maximum-port exhaustion: %v", err)
	}
}
