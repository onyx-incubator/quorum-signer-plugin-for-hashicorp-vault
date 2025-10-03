package main

import (
	"fmt"
	"os"

	signer "ethereum-signer-plugin/internal"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

// main is the entry point for the Quorum signer plugin for HashiCorp Vault.
// It initializes logging, handles error recovery, and starts the plugin server.
// The function will exit with status code 1 if any errors occur during startup.
func main() {
	// Initialize logger early for consistent error reporting
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "quorum-signer-plugin",
		Level: hclog.Info,
	})

	// Run main logic with proper error handling and panic recovery
	if err := runWithRecovery(logger); err != nil {
		logger.Error("plugin failed to start", "error", err)
		os.Exit(1)
	}
}

// runWithRecovery wraps the main run function with panic recovery to ensure
// that any panics are caught and converted to proper errors with logging.
// This provides a safety net for unexpected runtime panics that could crash
// the plugin server.
//
// Parameters:
//   - logger: The structured logger instance for error reporting
//
// Returns:
//   - error: Any error that occurred during execution or recovered from panic
func runWithRecovery(logger hclog.Logger) (retErr error) {
	// Recover from any panics and convert them to errors
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("panic occurred: %v", r)
			logger.Error("panic recovered", "panic", r)
		}
	}()

	return run(logger)
}

// run contains the main business logic for starting the Quorum signer plugin.
// It handles command-line flag parsing, TLS configuration, and starts the
// Vault plugin server with the appropriate backend factory.
//
// The function performs the following steps:
//  1. Validates the command-line environment
//  2. Parses Vault plugin flags for API client configuration
//  3. Configures TLS settings for secure communication
//  4. Creates and starts the plugin server with the signer backend
//
// Parameters:
//   - logger: The structured logger instance for operational logging
//
// Returns:
//   - error: Any error encountered during plugin initialization or server startup
func run(logger hclog.Logger) error {
	// Validate environment before proceeding
	if len(os.Args) == 0 {
		return fmt.Errorf("no command line arguments provided")
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	// Handle flag parsing errors with detailed context
	if err := flags.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("failed to parse command line flags: %w", err)
	}

	// Get TLS configuration
	tlsConfig := apiClientMeta.GetTLSConfig()
	if tlsConfig == nil {
		logger.Warn("no TLS configuration provided - plugin will run without TLS")
	}

	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	logger.Info("starting vault plugin server")

	// Create serve options and validate
	serveOpts := &plugin.ServeOpts{
		BackendFactoryFunc: signer.BackendFactory,
		TLSProviderFunc:    tlsProviderFunc,
	}

	// Start the plugin server with proper error handling
	if err := plugin.Serve(serveOpts); err != nil {
		return fmt.Errorf("plugin server failed: %w", err)
	}

	logger.Info("plugin server stopped gracefully")
	return nil
}
