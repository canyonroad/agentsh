//go:build fargate

package fargate

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// TaskDefParams holds parameters for building the ECS task definition.
type TaskDefParams struct {
	Family           string
	AgentshImage     string
	WorkloadImage    string
	ExecutionRoleARN string
	LogGroup         string
	LogStreamPrefix  string
	Region           string
}

// BuildTaskDefinition constructs the RegisterTaskDefinitionInput for the
// Fargate E2E test. Two containers share a PID namespace and a /shared volume.
func BuildTaskDefinition(p TaskDefParams) *ecs.RegisterTaskDefinitionInput {
	logOpts := func(name string) map[string]string {
		return map[string]string{
			"awslogs-group":         p.LogGroup,
			"awslogs-region":        p.Region,
			"awslogs-stream-prefix": p.LogStreamPrefix + "-" + name,
		}
	}

	return &ecs.RegisterTaskDefinitionInput{
		Family:                  aws.String(p.Family),
		NetworkMode:             ecstypes.NetworkModeAwsvpc,
		RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate},
		Cpu:                     aws.String("512"),
		Memory:                  aws.String("1024"),
		ExecutionRoleArn:        aws.String(p.ExecutionRoleARN),
		PidMode:                 ecstypes.PidModeTask,
		Volumes: []ecstypes.Volume{
			{Name: aws.String("shared")},
		},
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{
				Name:      aws.String("agentsh"),
				Image:     aws.String(p.AgentshImage),
				Essential: aws.Bool(true),
				LinuxParameters: &ecstypes.LinuxParameters{
					Capabilities: &ecstypes.KernelCapabilities{
						Add: []string{"SYS_PTRACE"},
					},
				},
				MountPoints: []ecstypes.MountPoint{
					{
						SourceVolume:  aws.String("shared"),
						ContainerPath: aws.String("/shared"),
					},
				},
				HealthCheck: &ecstypes.HealthCheck{
					Command:     []string{"CMD-SHELL", "test -f /tmp/healthy || exit 1"},
					Interval:    aws.Int32(5),
					Timeout:     aws.Int32(2),
					Retries:     aws.Int32(10),
					StartPeriod: aws.Int32(10),
				},
				LogConfiguration: &ecstypes.LogConfiguration{
					LogDriver: ecstypes.LogDriverAwslogs,
					Options:   logOpts("agentsh"),
				},
			},
			{
				Name:      aws.String("workload"),
				Image:     aws.String(p.WorkloadImage),
				Essential: aws.Bool(true),
				DependsOn: []ecstypes.ContainerDependency{
					{
						ContainerName: aws.String("agentsh"),
						Condition:     ecstypes.ContainerConditionHealthy,
					},
				},
				MountPoints: []ecstypes.MountPoint{
					{
						SourceVolume:  aws.String("shared"),
						ContainerPath: aws.String("/shared"),
					},
				},
				LogConfiguration: &ecstypes.LogConfiguration{
					LogDriver: ecstypes.LogDriverAwslogs,
					Options:   logOpts("workload"),
				},
			},
		},
	}
}

// BuildNetworkConfig constructs the ECS network configuration for RunTask.
func BuildNetworkConfig(subnetID, securityGroupID string) *ecstypes.NetworkConfiguration {
	return &ecstypes.NetworkConfiguration{
		AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
			Subnets:        []string{subnetID},
			SecurityGroups: []string{securityGroupID},
			AssignPublicIp: ecstypes.AssignPublicIpEnabled,
		},
	}
}
