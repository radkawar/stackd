// Package ports reserves native TCP endpoints before handing their exact ports
// to an engine. A range constrains only new automatic allocations.
package ports

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// ErrExhausted means every port in a configured range is already bound.
var ErrExhausted = errors.New("native TCP port pool exhausted")

// Range contains inclusive bounds. Its zero value uses OS ephemeral allocation.
// Explicit requested ports are exact and need not fall within these bounds.
type Range struct {
	First, Last uint16
}

// Parse accepts FIRST-LAST with nonzero decimal TCP ports, or an empty string
// for OS ephemeral allocation. A single-port range repeats its bound.
func Parse(value string) (Range, error) {
	if value == "" {
		return Range{}, nil
	}
	first, last, ok := strings.Cut(value, "-")
	if !ok || first == "" || last == "" {
		return Range{}, errors.New("native TCP port range must be FIRST-LAST")
	}
	parse := func(text string) (uint16, error) {
		for _, c := range text {
			if c < '0' || c > '9' {
				return 0, errors.New("native TCP port range requires decimal ports")
			}
		}
		n, err := strconv.ParseUint(text, 10, 16)
		if err != nil || n == 0 {
			return 0, errors.New("native TCP port range bounds must be between 1 and 65535")
		}
		return uint16(n), nil
	}
	start, err := parse(first)
	if err != nil {
		return Range{}, err
	}
	end, err := parse(last)
	if err != nil {
		return Range{}, err
	}
	r := Range{First: start, Last: end}
	return r, r.Validate()
}

// Validate accepts the zero range or nonzero ascending inclusive bounds.
func (r Range) Validate() error {
	if r == (Range{}) {
		return nil
	}
	if r.First == 0 || r.Last == 0 || r.First > r.Last {
		return errors.New("native TCP port range requires nonzero inclusive bounds in ascending order")
	}
	return nil
}

// Listen holds a real TCP socket until the caller closes it at engine handoff.
// Automatic selection tries the lowest available configured port first; there is
// no fallback outside the pool. Nonzero requested ports are never substituted.
// A competing claimant during handoff must be reported by the native engine.
func (r Range) Listen(ctx context.Context, host string, requested uint16) (net.Listener, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	listen := func(port uint16) (net.Listener, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var config net.ListenConfig
		return config.Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	}
	if requested != 0 || r == (Range{}) {
		return listen(requested)
	}
	// Use a wider counter so an inclusive Last=65535 cannot wrap to zero.
	for port := uint32(r.First); port <= uint32(r.Last); port++ {
		listener, err := listen(uint16(port))
		if err == nil {
			return listener, nil
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: %s:%d-%d", ErrExhausted, host, r.First, r.Last)
}
