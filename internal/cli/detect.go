package cli

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/spf13/cobra"
)

func newDetectCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect available security capabilities",
		Long: `Detect available security capabilities for the current platform.

This command probes the system for available security primitives like
seccomp, Landlock, eBPF, FUSE, and capabilities. It helps you understand
what security features are available in your environment.

Use 'agentsh detect config' to generate an optimized configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := capabilities.Detect()
			if err != nil {
				return fmt.Errorf("detection failed: %w", err)
			}

			var output []byte
			switch outputFormat {
			case "json":
				output, err = result.JSON()
			case "yaml":
				output, err = result.YAML()
			case "table":
				output = []byte(result.Table())
			default:
				return fmt.Errorf("unknown output format: %s", outputFormat)
			}

			if err != nil {
				return fmt.Errorf("format output: %w", err)
			}

			cmd.Println(string(output))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, yaml")

	cmd.AddCommand(newDetectConfigCmd())

	return cmd
}

func newDetectConfigCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Generate an optimized configuration",
		Long: `Generate an optimized security configuration based on detected capabilities.

By default, outputs to stdout. Use --output to write to a file.

Example:
  agentsh detect config                    # Print to stdout
  agentsh detect config --output config.yaml  # Write to file
  agentsh detect config > security.yaml    # Redirect to file`,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := capabilities.Detect()
			if err != nil {
				return fmt.Errorf("detection failed: %w", err)
			}

			config, err := capabilities.GenerateConfig(result)
			if err != nil {
				return fmt.Errorf("generate config: %w", err)
			}

			if outputPath != "" {
				if err := os.WriteFile(outputPath, config, 0644); err != nil {
					return fmt.Errorf("write config to %s: %w", outputPath, err)
				}
				cmd.Printf("Configuration written to %s\n", outputPath)
				return nil
			}

			cmd.Print(string(config))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout)")

	return cmd
}
