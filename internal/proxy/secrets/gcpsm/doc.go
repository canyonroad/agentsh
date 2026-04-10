// Package gcpsm implements secrets.SecretProvider using GCP Secret
// Manager. It wraps cloud.google.com/go/secretmanager/apiv1.
//
// GCP SM URIs take the form
//
//	gcp-sm://<name-or-prefix>[/<path>][#<field>]
//
// where <name-or-prefix> is the first segment of the secret name
// (the URI host), <path> is the rest of the name joined with "/",
// and the optional <field> selects one key from a JSON-valued
// secret.
//
// Auth uses Google Application Default Credentials (ADC): env var,
// gcloud CLI, GCE metadata, or Workload Identity Federation.
// No explicit credentials in config.
package gcpsm
