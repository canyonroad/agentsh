// Package fargate contains end-to-end tests that run on AWS Fargate.
//
// These tests require AWS credentials and are gated by the "fargate" build tag.
// They are not run as part of the normal test suite.
//
// Required environment variables:
//   - AWS_REGION
//   - AGENTSH_TEST_IMAGE (ECR URI for agentsh sidecar image)
//   - WORKLOAD_TEST_IMAGE (ECR URI for workload image)
//   - AWS_ECS_CLUSTER
//   - AWS_ECS_SUBNET
//   - AWS_ECS_SECURITY_GROUP
//   - AWS_ECS_EXECUTION_ROLE_ARN
package fargate
