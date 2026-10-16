package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteJobsSurviveRequestReturnAndDeduplicate(t *testing.T) {
	var count atomic.Int32
	release := make(chan struct{})
	manager := newJobManager(context.Background(), t.TempDir(), newProviderRuntime(), func(ctx context.Context, command string, out workerIO) (int, error) {
		count.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
			return 1, ctx.Err()
		}
		fmt.Fprint(out, "durable-result")
		return 0, nil
	})
	allow := func() bool { return true }
	request := jobRequest{Action: "submit", ID: "test-job-001", Command: "do something", TimeoutSeconds: 10}
	first := manager.request("owner", request, allow)
	if !first.OK || first.Code != "ACCEPTED" {
		t.Fatal(first)
	}
	again := manager.request("owner", request, allow)
	if !again.OK || again.Code != "EXISTING" {
		t.Fatal(again)
	}
	changed := request
	changed.Command = "different"
	if manager.request("owner", changed, allow).Code != "JOB_ID_CONFLICT" {
		t.Fatal("id reused")
	}
	if manager.request("other", jobRequest{Action: "status", ID: request.ID}, allow).OK {
		t.Fatal("cross-owner access")
	}
	close(release)
	var result jobReply
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		result = manager.request("owner", jobRequest{Action: "status", ID: request.ID}, allow)
		if result.Job.State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if result.Job.State != "completed" || *result.Job.ExitCode != 0 || count.Load() != 1 {
		t.Fatal(result, count.Load())
	}
	logs := manager.request("owner", jobRequest{Action: "logs", ID: request.ID, Stream: "stdout"}, allow)
	if string(logs.Data) != "durable-result" {
		t.Fatal(logs)
	}
	restarted := newJobManager(context.Background(), manager.root, nil, nil)
	if restarted.request("owner", request, allow).Code != "EXISTING" {
		t.Fatal("replayed completed job")
	}
}

func TestRemoteJobsCancelAndRevokeWithoutReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := newJobManager(ctx, t.TempDir(), nil, func(ctx context.Context, _ string, _ workerIO) (int, error) { <-ctx.Done(); return 1, ctx.Err() })
	allow := func() bool { return true }
	r := jobRequest{Action: "submit", ID: "cancel-job-001", Command: "wait", TimeoutSeconds: 20}
	if !manager.request("owner", r, allow).OK {
		t.Fatal("submit")
	}
	if manager.request("owner", jobRequest{Action: "cancel", ID: r.ID}, func() bool { return false }).Code != "JOB_ACCESS_REVOKED" {
		t.Fatal("revocation ignored")
	}
	manager.request("owner", jobRequest{Action: "cancel", ID: r.ID}, allow)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		result := manager.request("owner", jobRequest{Action: "status", ID: r.ID}, allow)
		if result.Job.State == "cancelled" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("cancel did not settle")
}

func TestCapacityValidationAndIdleDemand(t *testing.T) {
	for _, v := range []capacitySettings{{CallerConnections: -1}, {ProviderConnections: 129}, {MaxIdleChannels: 17}, {CallerQueue: 257}} {
		if (&Config{Capacity: v}).validateCapacity() == nil {
			t.Fatal(v)
		}
	}
	if desiredIdle(2, 16, 0) != 2 || desiredIdle(2, 16, 30) != 9 || desiredIdle(2, 16, 128) != 16 {
		t.Fatal("idle pool demand")
	}
}
