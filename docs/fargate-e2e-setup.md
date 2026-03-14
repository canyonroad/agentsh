# Fargate E2E Test Setup Guide

This guide walks through provisioning the AWS resources needed to run the
Fargate end-to-end tests for the ptrace tracer, and configuring GitHub
Actions to use them.

## Prerequisites

- AWS CLI v2 installed and configured (`aws sts get-caller-identity` succeeds)
- An AWS account with permissions to create ECS, ECR, VPC, IAM, and CloudWatch resources
- GitHub repository admin access (to set Actions variables and secrets)
- Docker installed locally (for initial image build verification)

## Step 1: Create ECR Repositories

Create two ECR repositories for the test images:

```bash
aws ecr create-repository \
  --repository-name agentsh-test \
  --image-scanning-configuration scanOnPush=false

aws ecr create-repository \
  --repository-name agentsh-fargate-workload \
  --image-scanning-configuration scanOnPush=false
```

Add a lifecycle policy to keep only the last 5 images (prevents unbounded
storage costs):

```bash
LIFECYCLE_POLICY='{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep last 5 images",
      "selection": {
        "tagStatus": "any",
        "countType": "imageCountMoreThan",
        "countNumber": 5
      },
      "action": {
        "type": "expire"
      }
    }
  ]
}'

aws ecr put-lifecycle-policy \
  --repository-name agentsh-test \
  --lifecycle-policy-text "$LIFECYCLE_POLICY"

aws ecr put-lifecycle-policy \
  --repository-name agentsh-fargate-workload \
  --lifecycle-policy-text "$LIFECYCLE_POLICY"
```

## Step 2: Create ECS Cluster

Create a Fargate-only ECS cluster (no EC2 capacity providers):

```bash
aws ecs create-cluster \
  --cluster-name agentsh-e2e \
  --capacity-providers FARGATE \
  --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1
```

## Step 3: Create VPC, Subnet, and Internet Gateway

The Fargate tasks need outbound internet access (for DNS tests and ECR pulls).

```bash
# Create VPC
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.0.0.0/24 \
  --query 'Vpc.VpcId' --output text)

aws ec2 create-tags --resources "$VPC_ID" \
  --tags Key=Name,Value=agentsh-e2e

# Enable DNS support
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support
aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames

# Create public subnet
SUBNET_ID=$(aws ec2 create-subnet \
  --vpc-id "$VPC_ID" \
  --cidr-block 10.0.0.0/24 \
  --query 'Subnet.SubnetId' --output text)

aws ec2 create-tags --resources "$SUBNET_ID" \
  --tags Key=Name,Value=agentsh-e2e-public

# Enable auto-assign public IP (needed for Fargate tasks with awsvpc)
aws ec2 modify-subnet-attribute \
  --subnet-id "$SUBNET_ID" \
  --map-public-ip-on-launch

# Create and attach internet gateway
IGW_ID=$(aws ec2 create-internet-gateway \
  --query 'InternetGateway.InternetGatewayId' --output text)

aws ec2 attach-internet-gateway \
  --internet-gateway-id "$IGW_ID" \
  --vpc-id "$VPC_ID"

# Add route to internet gateway in the main route table
RTB_ID=$(aws ec2 describe-route-tables \
  --filters Name=vpc-id,Values="$VPC_ID" \
  --query 'RouteTables[0].RouteTableId' --output text)

aws ec2 create-route \
  --route-table-id "$RTB_ID" \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id "$IGW_ID"

echo "VPC_ID=$VPC_ID"
echo "SUBNET_ID=$SUBNET_ID"
```

## Step 4: Create Security Group

Allow all egress (needed for outbound tests), no ingress:

```bash
SG_ID=$(aws ec2 create-security-group \
  --group-name agentsh-e2e \
  --description "agentsh Fargate E2E tests - egress only" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)

# Default security groups already allow all egress.
# Remove the default ingress rule that allows traffic from the same SG:
aws ec2 revoke-security-group-ingress \
  --group-id "$SG_ID" \
  --source-group "$SG_ID" \
  --protocol -1 2>/dev/null || true

echo "SG_ID=$SG_ID"
```

## Step 5: Create IAM Task Execution Role

The ECS task execution role allows Fargate to pull images from ECR and
write logs to CloudWatch:

```bash
# Create the role with ECS trust policy
aws iam create-role \
  --role-name agentsh-e2e-execution \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": { "Service": "ecs-tasks.amazonaws.com" },
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# Attach the managed ECS task execution policy (covers ECR pull + CW logs)
aws iam attach-role-policy \
  --role-name agentsh-e2e-execution \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Get the role ARN
EXECUTION_ROLE_ARN=$(aws iam get-role \
  --role-name agentsh-e2e-execution \
  --query 'Role.Arn' --output text)

echo "EXECUTION_ROLE_ARN=$EXECUTION_ROLE_ARN"
```

## Step 6: Create CloudWatch Log Group

```bash
aws logs create-log-group \
  --log-group-name /agentsh/fargate-e2e

aws logs put-retention-policy \
  --log-group-name /agentsh/fargate-e2e \
  --retention-in-days 7
```

## Step 7: Configure GitHub Actions

### Repository Variables

Set these as **repository variables** (Settings > Secrets and variables >
Actions > Variables tab):

| Variable | Value | Example |
|----------|-------|---------|
| `AWS_REGION` | AWS region where resources were created | `us-east-1` |
| `AWS_ECS_CLUSTER` | ECS cluster name | `agentsh-e2e` |
| `AWS_ECS_SUBNET` | Public subnet ID | `subnet-0abc123...` |
| `AWS_ECS_SECURITY_GROUP` | Security group ID | `sg-0abc123...` |
| `AWS_ECS_EXECUTION_ROLE_ARN` | Task execution role ARN | `arn:aws:iam::123456789012:role/agentsh-e2e-execution` |

### Repository Secrets

Set these as **repository secrets** (Settings > Secrets and variables >
Actions > Secrets tab):

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | IAM access key with ECR push + ECS run permissions |
| `AWS_SECRET_ACCESS_KEY` | Corresponding secret key |

The IAM user or role for CI needs these permissions:
- `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`
- `ecr:PutImage`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:BatchCheckLayerAvailability`
- `ecs:RegisterTaskDefinition`, `ecs:DeregisterTaskDefinition`, `ecs:RunTask`, `ecs:StopTask`, `ecs:DescribeTasks`
- `logs:GetLogEvents`
- `iam:PassRole` (for the execution role)

## Enabling and Disabling

**Enable:** Set the `AWS_ECS_CLUSTER` repository variable to your cluster
name. The CI job runs when this variable is non-empty.

**Disable:** Clear or delete the `AWS_ECS_CLUSTER` repository variable.
The job's `if` condition checks `vars.AWS_ECS_CLUSTER != ''` and skips
entirely when it is empty. No code changes needed.

The job also has `continue-on-error: true`, so even if the Fargate tests
fail, they will not block merges to main.

## Teardown

To remove all AWS resources:

```bash
# Delete ECS cluster (must have no running tasks)
aws ecs delete-cluster --cluster agentsh-e2e

# Delete ECR repositories (force deletes images)
aws ecr delete-repository --repository-name agentsh-test --force
aws ecr delete-repository --repository-name agentsh-fargate-workload --force

# Delete CloudWatch log group
aws logs delete-log-group --log-group-name /agentsh/fargate-e2e

# Delete IAM role (detach policy first)
aws iam detach-role-policy \
  --role-name agentsh-e2e-execution \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
aws iam delete-role --role-name agentsh-e2e-execution

# Delete security group
aws ec2 delete-security-group --group-id "$SG_ID"

# Detach and delete internet gateway
aws ec2 detach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"
aws ec2 delete-internet-gateway --internet-gateway-id "$IGW_ID"

# Delete subnet
aws ec2 delete-subnet --subnet-id "$SUBNET_ID"

# Delete VPC
aws ec2 delete-vpc --vpc-id "$VPC_ID"
```

Remove the `AWS_ECS_CLUSTER` repository variable and the `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` secrets from GitHub Actions settings.
