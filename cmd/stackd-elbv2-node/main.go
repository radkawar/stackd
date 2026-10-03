// stackd-elbv2-node is explicitly built with CGO_ENABLED=0 and installed by the
// operator. The ALB Docker adapter mounts it read-only into the owned namespace.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"stackd/compute/elbv2"
)

func main() {
	callback := flag.String("callback", "", "retained IPv4 gateway callback address")
	token := flag.String("token", "", "retained attachment callback token")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := elbv2.RunRelay(ctx, *callback, *token); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
