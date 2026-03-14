//go:build fargate

package fargate

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// runTask starts a Fargate task and returns the task ARN.
func runTask(ctx context.Context, client *ecs.Client, cluster string, taskDefARN string, netCfg *ecstypes.NetworkConfiguration) (string, error) {
	out, err := client.RunTask(ctx, &ecs.RunTaskInput{
		Cluster:              aws.String(cluster),
		TaskDefinition:       aws.String(taskDefARN),
		LaunchType:           ecstypes.LaunchTypeFargate,
		NetworkConfiguration: netCfg,
		Count:                aws.Int32(1),
	})
	if err != nil {
		return "", fmt.Errorf("RunTask: %w", err)
	}
	if len(out.Failures) > 0 {
		return "", fmt.Errorf("RunTask failure: %s — %s", aws.ToString(out.Failures[0].Reason), aws.ToString(out.Failures[0].Detail))
	}
	if len(out.Tasks) == 0 {
		return "", fmt.Errorf("RunTask returned no tasks")
	}
	return aws.ToString(out.Tasks[0].TaskArn), nil
}

// waitForTask polls DescribeTasks until the task reaches STOPPED or the context expires.
func waitForTask(ctx context.Context, client *ecs.Client, cluster, taskARN string, timeout time.Duration) (*ecstypes.Task, error) {
	deadline := time.Now().Add(timeout)
	lastStatus := ""

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		out, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: aws.String(cluster),
			Tasks:   []string{taskARN},
		})
		if err != nil {
			return nil, fmt.Errorf("DescribeTasks: %w", err)
		}
		if len(out.Tasks) == 0 {
			return nil, fmt.Errorf("DescribeTasks returned no tasks")
		}

		task := out.Tasks[0]
		status := aws.ToString(task.LastStatus)
		if status != lastStatus {
			slog.Info("task status", "status", status, "task", taskARN)
			lastStatus = status
		}

		if status == "STOPPED" {
			return &task, nil
		}

		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("task did not reach STOPPED within %v (last status: %s)", timeout, lastStatus)
}

// stopTask stops a running task.
func stopTask(ctx context.Context, client *ecs.Client, cluster, taskARN, reason string) error {
	_, err := client.StopTask(ctx, &ecs.StopTaskInput{
		Cluster: aws.String(cluster),
		Task:    aws.String(taskARN),
		Reason:  aws.String(reason),
	})
	return err
}

// deregisterTaskDef deregisters a task definition revision.
func deregisterTaskDef(ctx context.Context, client *ecs.Client, taskDefARN string) error {
	_, err := client.DeregisterTaskDefinition(ctx, &ecs.DeregisterTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefARN),
	})
	return err
}

// fetchLogs retrieves CloudWatch log events for log streams matching a prefix, with retry.
func fetchLogs(ctx context.Context, client *cloudwatchlogs.Client, logGroup, logStreamPrefix string, maxRetries int) ([]string, error) {
	var lines []string

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			if backoff > 15*time.Second {
				backoff = 15 * time.Second
			}
			slog.Info("retrying log fetch", "attempt", attempt, "backoff", backoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		streams, err := client.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
			LogGroupName:        aws.String(logGroup),
			LogStreamNamePrefix: aws.String(logStreamPrefix),
		})
		if err != nil {
			continue
		}
		if len(streams.LogStreams) == 0 {
			continue
		}

		lines = nil
		for _, stream := range streams.LogStreams {
			events, err := getAllLogEvents(ctx, client, logGroup, aws.ToString(stream.LogStreamName))
			if err != nil {
				continue
			}
			for _, event := range events {
				lines = append(lines, aws.ToString(event.Message))
			}
		}

		if len(lines) > 0 {
			return lines, nil
		}
	}

	if len(lines) == 0 {
		return nil, fmt.Errorf("no logs found for prefix %q after %d retries", logStreamPrefix, maxRetries)
	}
	return lines, nil
}

// getAllLogEvents paginates through all events in a log stream.
func getAllLogEvents(ctx context.Context, client *cloudwatchlogs.Client, logGroup, logStream string) ([]cwltypes.OutputLogEvent, error) {
	var allEvents []cwltypes.OutputLogEvent
	var nextToken *string

	for {
		out, err := client.GetLogEvents(ctx, &cloudwatchlogs.GetLogEventsInput{
			LogGroupName:  aws.String(logGroup),
			LogStreamName: aws.String(logStream),
			StartFromHead: aws.Bool(true),
			NextToken:     nextToken,
		})
		if err != nil {
			return nil, err
		}
		allEvents = append(allEvents, out.Events...)

		if nextToken != nil && aws.ToString(out.NextForwardToken) == aws.ToString(nextToken) {
			break
		}
		nextToken = out.NextForwardToken
		if len(out.Events) == 0 {
			break
		}
	}

	return allEvents, nil
}

// taskDiagnostics extracts diagnostic information from a stopped task.
func taskDiagnostics(task *ecstypes.Task) string {
	diag := fmt.Sprintf("stopped reason: %s\n", aws.ToString(task.StoppedReason))
	for _, c := range task.Containers {
		exitCode := "n/a"
		if c.ExitCode != nil {
			exitCode = fmt.Sprintf("%d", *c.ExitCode)
		}
		reason := aws.ToString(c.Reason)
		diag += fmt.Sprintf("  container %s: exit=%s status=%s reason=%s\n",
			aws.ToString(c.Name), exitCode, aws.ToString(c.LastStatus), reason)
	}
	return diag
}
