//go:build linux

package main

import (
	"fmt"
	"os"

	"stackd/compute/lambda"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: telemetry-buffer CALLBACK_URL")
		os.Exit(2)
	}
	if err := lambda.RunTelemetryBuffer(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
