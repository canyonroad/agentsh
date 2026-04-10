// Package awssm implements secrets.SecretProvider using AWS Secrets
// Manager. It wraps github.com/aws/aws-sdk-go-v2/service/secretsmanager.
//
// AWS SM URIs take the form
//
//	aws-sm://<name-or-prefix>[/<path>][#<field>]
//
// where <name-or-prefix> is the first segment of the secret name
// (the URI host), <path> is the rest of the name joined with "/",
// and the optional <field> selects one key from a JSON-valued
// secret.
//
// Auth uses the standard AWS SDK default credential chain: env vars,
// shared credentials file, IRSA, ECS task role, or EC2 instance
// profile. No explicit credentials in config.
package awssm
