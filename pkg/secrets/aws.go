package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSProvider provides secrets from AWS Secrets Manager.
type AWSProvider struct {
	cfg    AWSConfig
	client *secretsmanager.Client
}

// NewAWSProvider creates a new AWS Secrets Manager provider.
func NewAWSProvider(ctx context.Context, cfg AWSConfig) (*AWSProvider, error) {
	if cfg.Region == "" {
		return nil, fmt.Errorf("aws region required")
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("loading aws config: %w", err)
	}

	// Assume role if specified
	if cfg.RoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleARN)
		awsCfg.Credentials = aws.NewCredentialsCache(creds)
	}

	client := secretsmanager.NewFromConfig(awsCfg)

	return &AWSProvider{
		cfg:    cfg,
		client: client,
	}, nil
}

// Name returns the provider name.
func (p *AWSProvider) Name() string {
	return "aws"
}

// Get retrieves a secret from AWS Secrets Manager.
func (p *AWSProvider) Get(ctx context.Context, path string) (*Secret, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(path),
	}

	result, err := p.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("getting secret: %w", err)
	}

	secret := &Secret{
		Path:     path,
		Metadata: make(map[string]string),
	}

	if result.VersionId != nil {
		secret.Version = *result.VersionId
	}

	if result.CreatedDate != nil {
		secret.CreatedAt = *result.CreatedDate
	}

	// Parse secret value
	if result.SecretString != nil {
		// Try to parse as JSON
		var data map[string]string
		if err := json.Unmarshal([]byte(*result.SecretString), &data); err == nil {
			secret.Data = data
		} else {
			// Store as single value
			secret.Data = map[string]string{
				"value": *result.SecretString,
			}
		}
	} else if result.SecretBinary != nil {
		// Binary secret
		secret.Data = map[string]string{
			"binary": string(result.SecretBinary),
		}
	}

	// Add ARN to metadata
	if result.ARN != nil {
		secret.Metadata["arn"] = *result.ARN
	}

	return secret, nil
}

// List lists secrets with a given prefix.
func (p *AWSProvider) List(ctx context.Context, prefix string) ([]string, error) {
	input := &secretsmanager.ListSecretsInput{}

	if prefix != "" {
		input.Filters = []types.Filter{
			{
				Key:    types.FilterNameStringTypeName,
				Values: []string{prefix},
			},
		}
	}

	var secrets []string
	paginator := secretsmanager.NewListSecretsPaginator(p.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}

		for _, s := range page.SecretList {
			if s.Name != nil {
				secrets = append(secrets, *s.Name)
			}
		}
	}

	return secrets, nil
}

// IsHealthy checks if AWS Secrets Manager is accessible.
func (p *AWSProvider) IsHealthy(ctx context.Context) bool {
	// Try to list secrets with a limit of 1 to verify access
	input := &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	}

	_, err := p.client.ListSecrets(ctx, input)
	return err == nil
}

// CreateSecret creates a new secret.
func (p *AWSProvider) CreateSecret(ctx context.Context, name, description string, data map[string]string) (*Secret, error) {
	secretValue, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling secret data: %w", err)
	}

	input := &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		Description:  aws.String(description),
		SecretString: aws.String(string(secretValue)),
	}

	result, err := p.client.CreateSecret(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("creating secret: %w", err)
	}

	return &Secret{
		Path:      name,
		Data:      data,
		Version:   *result.VersionId,
		CreatedAt: time.Now(),
		Metadata: map[string]string{
			"arn": *result.ARN,
		},
	}, nil
}

// UpdateSecret updates an existing secret.
func (p *AWSProvider) UpdateSecret(ctx context.Context, name string, data map[string]string) (*Secret, error) {
	secretValue, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling secret data: %w", err)
	}

	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(name),
		SecretString: aws.String(string(secretValue)),
	}

	result, err := p.client.PutSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("updating secret: %w", err)
	}

	return &Secret{
		Path:    name,
		Data:    data,
		Version: *result.VersionId,
		Metadata: map[string]string{
			"arn": *result.ARN,
		},
	}, nil
}

// DeleteSecret deletes a secret.
func (p *AWSProvider) DeleteSecret(ctx context.Context, name string, forceDelete bool) error {
	input := &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(name),
		ForceDeleteWithoutRecovery: aws.Bool(forceDelete),
	}

	_, err := p.client.DeleteSecret(ctx, input)
	if err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}

	return nil
}

// RotateSecret triggers rotation for a secret.
func (p *AWSProvider) RotateSecret(ctx context.Context, name string) error {
	input := &secretsmanager.RotateSecretInput{
		SecretId: aws.String(name),
	}

	_, err := p.client.RotateSecret(ctx, input)
	if err != nil {
		return fmt.Errorf("rotating secret: %w", err)
	}

	return nil
}

// GetSecretVersions lists all versions of a secret.
func (p *AWSProvider) GetSecretVersions(ctx context.Context, name string) ([]SecretVersion, error) {
	input := &secretsmanager.ListSecretVersionIdsInput{
		SecretId: aws.String(name),
	}

	var versions []SecretVersion
	paginator := secretsmanager.NewListSecretVersionIdsPaginator(p.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing versions: %w", err)
		}

		for _, v := range page.Versions {
			version := SecretVersion{
				VersionID: *v.VersionId,
			}
			if v.CreatedDate != nil {
				version.CreatedAt = *v.CreatedDate
			}
			for _, stage := range v.VersionStages {
				version.Stages = append(version.Stages, stage)
			}
			versions = append(versions, version)
		}
	}

	return versions, nil
}

// SecretVersion represents a version of a secret.
type SecretVersion struct {
	VersionID string    `json:"version_id"`
	CreatedAt time.Time `json:"created_at"`
	Stages    []string  `json:"stages"`
}
