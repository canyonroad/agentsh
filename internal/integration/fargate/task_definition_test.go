//go:build fargate

package fargate

import (
	"testing"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestBuildTaskDefinition(t *testing.T) {
	params := TaskDefParams{
		Family:           "agentsh-e2e-test",
		AgentshImage:     "123456789.dkr.ecr.us-east-1.amazonaws.com/agentsh-test:abc123",
		WorkloadImage:    "123456789.dkr.ecr.us-east-1.amazonaws.com/agentsh-fargate-workload:abc123",
		ExecutionRoleARN: "arn:aws:iam::123456789:role/ecsTaskExecutionRole",
		LogGroup:         "/agentsh/fargate-e2e",
		LogStreamPrefix:  "test-run-1",
		Region:           "us-east-1",
	}

	input := BuildTaskDefinition(params)

	// Verify top-level task settings
	if *input.Family != params.Family {
		t.Errorf("family = %q, want %q", *input.Family, params.Family)
	}
	if string(input.NetworkMode) != "awsvpc" {
		t.Errorf("network mode = %q, want awsvpc", input.NetworkMode)
	}
	if input.PidMode != ecstypes.PidModeTask {
		t.Errorf("pid mode = %q, want task", input.PidMode)
	}
	if *input.Cpu != "512" {
		t.Errorf("cpu = %q, want 512", *input.Cpu)
	}
	if *input.Memory != "1024" {
		t.Errorf("memory = %q, want 1024", *input.Memory)
	}

	// Verify two containers
	if len(input.ContainerDefinitions) != 2 {
		t.Fatalf("container count = %d, want 2", len(input.ContainerDefinitions))
	}

	// Find containers by name
	var agentsh, workload *ecstypes.ContainerDefinition
	for i := range input.ContainerDefinitions {
		switch *input.ContainerDefinitions[i].Name {
		case "agentsh":
			agentsh = &input.ContainerDefinitions[i]
		case "workload":
			workload = &input.ContainerDefinitions[i]
		}
	}
	if agentsh == nil {
		t.Fatal("agentsh container not found")
	}
	if workload == nil {
		t.Fatal("workload container not found")
	}

	// Verify agentsh has SYS_PTRACE
	if agentsh.LinuxParameters == nil || agentsh.LinuxParameters.Capabilities == nil {
		t.Fatal("agentsh missing linux parameters / capabilities")
	}
	hasPtrace := false
	for _, cap := range agentsh.LinuxParameters.Capabilities.Add {
		if cap == "SYS_PTRACE" {
			hasPtrace = true
		}
	}
	if !hasPtrace {
		t.Error("agentsh missing SYS_PTRACE capability")
	}

	// Verify shared volume
	if len(input.Volumes) != 1 {
		t.Fatalf("volume count = %d, want 1", len(input.Volumes))
	}
	if *input.Volumes[0].Name != "shared" {
		t.Errorf("volume name = %q, want shared", *input.Volumes[0].Name)
	}

	// Verify both containers mount the shared volume
	for _, c := range []*ecstypes.ContainerDefinition{agentsh, workload} {
		found := false
		for _, mp := range c.MountPoints {
			if *mp.SourceVolume == "shared" && *mp.ContainerPath == "/shared" {
				found = true
			}
		}
		if !found {
			t.Errorf("container %q missing /shared mount", *c.Name)
		}
	}

	// Verify workload depends on agentsh being HEALTHY
	if len(workload.DependsOn) == 0 {
		t.Fatal("workload has no dependsOn")
	}
	depFound := false
	for _, dep := range workload.DependsOn {
		if *dep.ContainerName == "agentsh" && dep.Condition == ecstypes.ContainerConditionHealthy {
			depFound = true
		}
	}
	if !depFound {
		t.Error("workload does not depend on agentsh HEALTHY")
	}

	// Verify execution role
	if *input.ExecutionRoleArn != params.ExecutionRoleARN {
		t.Errorf("execution role = %q, want %q", *input.ExecutionRoleArn, params.ExecutionRoleARN)
	}

	// Verify both containers have CloudWatch logging
	for _, c := range []*ecstypes.ContainerDefinition{agentsh, workload} {
		if c.LogConfiguration == nil {
			t.Errorf("container %q missing log configuration", *c.Name)
			continue
		}
		if c.LogConfiguration.LogDriver != ecstypes.LogDriverAwslogs {
			t.Errorf("container %q log driver = %q, want awslogs", *c.Name, c.LogConfiguration.LogDriver)
		}
		opts := c.LogConfiguration.Options
		if opts["awslogs-group"] != params.LogGroup {
			t.Errorf("container %q log group = %q, want %q", *c.Name, opts["awslogs-group"], params.LogGroup)
		}
		if opts["awslogs-region"] != params.Region {
			t.Errorf("container %q log region = %q, want %q", *c.Name, opts["awslogs-region"], params.Region)
		}
	}

	// Verify agentsh marked essential
	if agentsh.Essential == nil || !*agentsh.Essential {
		t.Error("agentsh not marked essential")
	}

	// Verify Fargate compatibility
	found := false
	for _, compat := range input.RequiresCompatibilities {
		if compat == ecstypes.CompatibilityFargate {
			found = true
		}
	}
	if !found {
		t.Error("missing FARGATE compatibility requirement")
	}
}

func TestBuildNetworkConfig(t *testing.T) {
	nc := BuildNetworkConfig("subnet-abc123", "sg-def456")

	if nc.AwsvpcConfiguration == nil {
		t.Fatal("missing AwsvpcConfiguration")
	}
	cfg := nc.AwsvpcConfiguration
	if len(cfg.Subnets) != 1 || cfg.Subnets[0] != "subnet-abc123" {
		t.Errorf("subnets = %v, want [subnet-abc123]", cfg.Subnets)
	}
	if len(cfg.SecurityGroups) != 1 || cfg.SecurityGroups[0] != "sg-def456" {
		t.Errorf("security groups = %v, want [sg-def456]", cfg.SecurityGroups)
	}
	if cfg.AssignPublicIp != ecstypes.AssignPublicIpEnabled {
		t.Errorf("assign public ip = %q, want ENABLED", cfg.AssignPublicIp)
	}
}
