package network

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// Called serially by the native replay suite. A source mismatch must not turn
// collector adoption into authority to stop an unrecognized retained process.
func testFlowCollectorRejectsUnknownReceiverRevision(t *testing.T) {
	client := daemonNetworkTestEngine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	current := flowReceiverScript
	t.Cleanup(func() { flowReceiverScript = current })
	flowReceiverScript += "\n# unrecognized retained revision\n"
	collector, err := NewDockerFlowCollector(client, "native-flow-unknown-revision-"+rand.Text())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := client.RemoveContainer(cleanup, collector.name); err != nil {
			t.Error(err)
		}
		if err := client.JSON(cleanup, "DELETE", "/volumes/"+collector.volume, nil, nil); err != nil {
			t.Error(err)
		}
	})
	if err := collector.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	var before struct {
		ID    string `json:"Id"`
		State struct{ Running bool }
	}
	if err := client.JSON(ctx, "GET", "/containers/"+collector.name+"/json", nil, &before); err != nil {
		t.Fatal(err)
	}
	flowReceiverScript = current
	if err := collector.Ensure(ctx); err == nil || !strings.Contains(err.Error(), "unrecognized receiver revision") {
		t.Fatalf("unknown receiver admission did not fail closed: %v", err)
	}
	var after struct {
		ID    string `json:"Id"`
		State struct{ Running bool }
	}
	if err := client.JSON(ctx, "GET", "/containers/"+collector.name+"/json", nil, &after); err != nil {
		t.Fatal(err)
	}
	if before.ID == "" || before.ID != after.ID || !before.State.Running || !after.State.Running {
		t.Fatalf("refused revision was stopped or replaced: before=%+v after=%+v", before, after)
	}
}
