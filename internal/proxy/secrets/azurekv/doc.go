// Package azurekv implements secrets.SecretProvider using Azure Key Vault.
// It wraps github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets.
//
// Azure KV URIs take the form
//
//	azure-kv://<secret-name>[#<field>]
//
// where <secret-name> is the URI host. Azure Key Vault secret names
// allow only alphanumerics and hyphens -- forward slashes are not valid.
// If the URI contains a path component, Fetch returns ErrInvalidURI.
//
// Auth uses Azure DefaultAzureCredential: env vars, Managed Identity,
// Azure CLI, or Azure Developer CLI. No explicit credentials in config.
package azurekv
