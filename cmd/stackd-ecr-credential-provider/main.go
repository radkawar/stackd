// stackd-ecr-credential-provider is invoked by the native worker's kubelet.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"stackd/compute/eks/ecrcredentials"
)

func main() {
	config := flag.String("config", "", "private node ECR credentials JSON")
	ca := flag.String("ca", "", "trusted ECR CA PEM")
	flag.Parse()
	if err := ecrcredentials.Run(context.Background(), *config, *ca, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "stackd-ecr-credential-provider:", err)
		os.Exit(1)
	}
}
