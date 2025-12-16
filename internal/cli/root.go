package cli

import (
	"os"

	"github.com/spf13/cobra"
)

func NewRoot(version string) *cobra.Command {
	cfg := &clientConfig{}
	cmd := &cobra.Command{
		Use:           "agentsh",
		Short:         "agentsh: secure agent shell",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Version = version
	cmd.SetVersionTemplate("agentsh {{.Version}}\n")

	cmd.PersistentFlags().StringVar(&cfg.serverAddr, "server", getenvDefault("AGENTSH_SERVER", "http://127.0.0.1:8080"), "agentsh server base URL")
	cmd.PersistentFlags().StringVar(&cfg.apiKey, "api-key", getenvDefault("AGENTSH_API_KEY", ""), "API key (sent as X-API-Key)")

	cmd.AddCommand(newServerCmd())
	cmd.AddCommand(newSessionCmd())
	cmd.AddCommand(newExecCmd())
	cmd.AddCommand(newKillCmd())
	cmd.AddCommand(newEventsCmd())
	cmd.AddCommand(newOutputCmd())
	cmd.AddCommand(newApproveCmd())

	return cmd
}

type clientConfig struct {
	serverAddr string
	apiKey     string
}

func getClientConfig(cmd *cobra.Command) *clientConfig {
	serverAddr, _ := cmd.Root().PersistentFlags().GetString("server")
	apiKey, _ := cmd.Root().PersistentFlags().GetString("api-key")
	if serverAddr == "" {
		serverAddr = "http://127.0.0.1:8080"
	}
	return &clientConfig{serverAddr: serverAddr, apiKey: apiKey}
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
