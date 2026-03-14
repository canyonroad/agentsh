//go:build fargate

package fargate

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("skipping: %s not set", key)
	}
	return v
}

func TestFargateE2E(t *testing.T) {
	cluster := requiredEnv(t, "AWS_ECS_CLUSTER")
	subnet := requiredEnv(t, "AWS_ECS_SUBNET")
	sg := requiredEnv(t, "AWS_ECS_SECURITY_GROUP")
	execRole := requiredEnv(t, "AWS_ECS_EXECUTION_ROLE_ARN")
	agentshImage := requiredEnv(t, "AGENTSH_TEST_IMAGE")
	workloadImage := requiredEnv(t, "WORKLOAD_TEST_IMAGE")
	region := requiredEnv(t, "AWS_REGION")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
	ecsClient := ecs.NewFromConfig(cfg)
	cwlClient := cloudwatchlogs.NewFromConfig(cfg)

	runID := time.Now().Format("20060102-150405")
	logGroup := "/agentsh/fargate-e2e"
	logStreamPrefix := "test-" + runID

	taskDefInput := BuildTaskDefinition(TaskDefParams{
		Family:           "agentsh-e2e-" + runID,
		AgentshImage:     agentshImage,
		WorkloadImage:    workloadImage,
		ExecutionRoleARN: execRole,
		LogGroup:         logGroup,
		LogStreamPrefix:  logStreamPrefix,
		Region:           region,
	})

	regOut, err := ecsClient.RegisterTaskDefinition(ctx, taskDefInput)
	if err != nil {
		t.Fatalf("register task definition: %v", err)
	}
	taskDefARN := aws.ToString(regOut.TaskDefinition.TaskDefinitionArn)
	t.Logf("registered task definition: %s", taskDefARN)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := deregisterTaskDef(cleanupCtx, ecsClient, taskDefARN); err != nil {
			t.Logf("cleanup: deregister task def: %v", err)
		}
	})

	netCfg := BuildNetworkConfig(subnet, sg)
	taskARN, err := runTask(ctx, ecsClient, cluster, taskDefARN, netCfg)
	if err != nil {
		t.Fatalf("run task: %v", err)
	}
	t.Logf("task started: %s", taskARN)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = stopTask(cleanupCtx, ecsClient, cluster, taskARN, "E2E test cleanup")
	})

	task, err := waitForTask(ctx, ecsClient, cluster, taskARN, 5*time.Minute)
	if err != nil {
		_ = stopTask(ctx, ecsClient, cluster, taskARN, "E2E test timeout")
		t.Fatalf("wait for task: %v", err)
	}

	t.Logf("task diagnostics:\n%s", taskDiagnostics(task))

	workloadLogs, err := fetchLogs(ctx, cwlClient, logGroup, logStreamPrefix+"-workload", 5)
	if err != nil {
		t.Fatalf("fetch workload logs: %v", err)
	}
	t.Logf("workload logs (%d lines):", len(workloadLogs))
	for _, line := range workloadLogs {
		t.Logf("  %s", line)
	}

	agentshLogs, err := fetchLogs(ctx, cwlClient, logGroup, logStreamPrefix+"-agentsh", 5)
	if err != nil {
		t.Fatalf("fetch agentsh logs: %v", err)
	}
	t.Logf("agentsh logs (%d lines):", len(agentshLogs))
	for _, line := range agentshLogs {
		t.Logf("  %s", line)
	}

	result := ParseWorkloadLogs(workloadLogs)

	if !result.Complete {
		t.Error("workload test did not complete (missing DONE marker)")
	}

	// Positive controls: if missing, environment is broken
	if ctrl, ok := result.Results["CONTROL"]; !ok {
		t.Error("INFRASTRUCTURE FAILURE: positive control (CONTROL) not found — test environment is broken, not policy")
	} else if !ctrl.Pass {
		t.Errorf("INFRASTRUCTURE FAILURE: positive control failed: %s", ctrl.Detail)
	}

	if fctrl, ok := result.Results["FILECONTROL"]; !ok {
		t.Error("INFRASTRUCTURE FAILURE: file write control (FILECONTROL) not found")
	} else if !fctrl.Pass {
		t.Errorf("INFRASTRUCTURE FAILURE: file write control failed: %s — writes broken, FILE test unreliable", fctrl.Detail)
	}

	if setup, ok := result.Results["SETUP"]; !ok {
		t.Fatal("SETUP result not found in workload output")
	} else if !setup.Pass {
		t.Fatalf("setup failed: %s", setup.Detail)
	}

	// Policy enforcement checks
	for _, name := range []string{"EXEC", "FILE", "NET"} {
		r, ok := result.Results[name]
		if !ok {
			t.Errorf("missing %s test result", name)
			continue
		}
		if !r.Pass {
			t.Errorf("%s test failed: %s", name, r.Detail)
		}
	}

	t.Logf("seccomp probe result: %s", result.SeccompAvailable)

	events := ParseAuditEvents(agentshLogs)
	t.Logf("found %d audit events", len(events))

	denyEvents := 0
	for _, e := range events {
		if e.Action == "deny" {
			denyEvents++
			t.Logf("  deny event: syscall=%s fields=%v", e.Syscall, e.Fields)
		}
	}
	if denyEvents == 0 {
		t.Error("no deny audit events found in agentsh logs — tracer may not be making enforcement decisions")
	}
}
