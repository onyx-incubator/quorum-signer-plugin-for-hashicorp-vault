// Package internal provides the backend implementation for the Quorum signer plugin for HashiCorp Vault.
// This package handles the configuration and routing of account management and cryptographic signing operations.
package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Storage path constants for organizing data within Vault's storage backend.
const (
	// acctPath is the storage path prefix for account address data
	acctPath = "accounts"
	// signPath is the API path prefix for signing operations
	signPath = "sign"
	// keyPath is the storage path prefix for private key data
	keyPath = "keys"
)

// Custom error types for better error categorization and handling.
var (
	// ErrInvalidBackendConfig is returned when backend configuration parameters are invalid
	ErrInvalidBackendConfig = errors.New("invalid backend configuration")
	// ErrBackendSetupFailed is returned when the Vault framework backend setup fails
	ErrBackendSetupFailed = errors.New("backend setup failed")
)

// backend represents the main backend struct that implements the logical.Backend interface
// for the Quorum signer plugin. It embeds the Vault framework's Backend to provide
// standard plugin functionality while adding custom path handlers for account operations.
type backend struct {
	*framework.Backend
}

// BackendFactory creates and configures a new backend instance for the Quorum signer plugin.
// It validates the input parameters and sets up the backend with proper error handling.
// This function is called by Vault during plugin initialization and must return a configured
// logical.Backend implementation.
//
// The factory performs the following operations:
//  1. Validates input parameters (context and configuration)
//  2. Creates a new backend instance with path configurations
//  3. Initializes the Vault framework backend with seal-wrap storage for sensitive paths
//  4. Calls the framework's Setup method to complete initialization
//
// Parameters:
//   - ctx: The context for the backend initialization, used for cancellation and timeouts
//   - conf: The backend configuration provided by Vault containing storage and system view
//
// Returns:
//   - logical.Backend: The configured backend instance ready to handle requests
//   - error: Any error encountered during backend creation or setup
func BackendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	// Validate input parameters
	if ctx == nil {
		return nil, fmt.Errorf("%w: context cannot be nil", ErrInvalidBackendConfig)
	}
	if conf == nil {
		return nil, fmt.Errorf("%w: backend configuration cannot be nil", ErrInvalidBackendConfig)
	}

	b := new(backend)
	if b == nil {
		return nil, fmt.Errorf("failed to allocate memory for backend")
	}

	// Validate path configuration
	paths := []*framework.Path{
		b.accountIDPath(),
		b.signPath(),
	}

	for i, path := range paths {
		if path == nil {
			return nil, fmt.Errorf("path configuration %d is nil", i)
		}
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace("Creates and stores Quorum accounts.  Signs data using those accounts.\n"),
		BackendType: logical.TypeLogical,
		Paths:       paths,
		PathsSpecial: &logical.Paths{
			// paths to encrypt when sealed
			SealWrapStorage: []string{
				fmt.Sprintf("%s/", acctPath),
				fmt.Sprintf("%s/", keyPath),
			},
		},
	}

	// Validate backend was created successfully
	if b.Backend == nil {
		return nil, fmt.Errorf("failed to create framework backend")
	}

	// Setup backend with proper error handling
	if err := b.Backend.Setup(ctx, conf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackendSetupFailed, err)
	}

	return b, nil
}

// accountIDPath defines the path configuration for account operations with enhanced validation.
// This method creates and returns a framework.Path that handles all account-related operations
// including creation, reading, updating, and listing of Ethereum/Quorum accounts.
//
// The path supports the following operations:
//   - READ: Retrieve account address for a given account ID
//   - CREATE: Generate new account or import existing account from private key
//   - UPDATE: Same as CREATE (determines operation based on account existence)
//   - LIST: List all available account IDs
//
// Field validation is handled through the framework's field schema, and all operations
// are wrapped with validation functions to ensure proper error handling.
//
// Returns:
//   - *framework.Path: The configured path for account operations, or nil if backend is invalid
func (b *backend) accountIDPath() *framework.Path {
	if b == nil {
		// This should never happen, but defensive programming
		return nil
	}

	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", acctPath, framework.MatchAllRegex("acctID")),

		Fields: map[string]*framework.FieldSchema{
			"acctID": {
				Type:        framework.TypeString,
				Description: "Specifies the path of the account.",
				Required:    true,
			},
			"import": {
				Type:        framework.TypeString,
				Description: "(optional) A hex-encoded private key to imported and store at the specified path.",
				Required:    false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.readAccountWithValidation,
				Summary:  "Read account address",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.createAccountWithValidation,
				Summary:  "Generate and store new Quorum account, or import existing account by using the 'import' field.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.updateAccountWithValidation,
				Summary:  "Generate and store new Quorum account, or import existing account by using the 'import' field.",
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.listAccountIDsWithValidation,
				Summary:  "List account IDs",
			},
		},
		ExistenceCheck: b.accountExistenceCheckWithValidation, // determines whether create or update operation is called
	}
}

// signPath defines the path configuration for signing operations with enhanced validation.
// This method creates and returns a framework.Path that handles cryptographic signing
// operations using stored account private keys.
//
// The path supports READ operations that:
//  1. Validate the account ID and hex data to be signed
//  2. Retrieve the private key from secure storage
//  3. Perform ECDSA signature generation
//  4. Return the signature in hex format
//
// All signing operations require both an account ID (in the path) and hex-encoded data
// to sign (in the request body). The operation is wrapped with validation to ensure
// proper error handling and input validation.
//
// Returns:
//   - *framework.Path: The configured path for signing operations, or nil if backend is invalid
func (b *backend) signPath() *framework.Path {
	if b == nil {
		// This should never happen, but defensive programming
		return nil
	}

	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", signPath, framework.MatchAllRegex("acctID")),

		Fields: map[string]*framework.FieldSchema{
			"acctID": {
				Type:        framework.TypeString,
				Description: "Specifies the path of the account.",
				Required:    true,
			},
			"sign": {
				Type:        framework.TypeString,
				Description: "Hex-encoded payload to be signed.",
				Required:    true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.signWithValidation,
				Summary:  "Sign data with account, returns hex-encoded signature in r,s,v format where v is 0 or 1",
			},
		},
	}
}

// validateOperation performs common validation for all operations to ensure consistent
// error handling across all backend methods. This centralizes the validation logic
// and prevents code duplication while ensuring all critical parameters are validated
// before proceeding with any operation.
//
// The function validates:
//   - Context is not nil (required for cancellation and timeouts)
//   - Request is not nil (contains path, storage, and operation metadata)
//   - Storage is not nil (required for data persistence operations)
//   - Field data is not nil (contains request parameters and user input)
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing storage and metadata
//   - d: The field data containing request parameters
//
// Returns:
//   - error: Any validation error encountered, or nil if all validations pass
func (b *backend) validateOperation(ctx context.Context, req *logical.Request, d *framework.FieldData) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.Storage == nil {
		return fmt.Errorf("storage cannot be nil")
	}
	if d == nil {
		return fmt.Errorf("field data cannot be nil")
	}
	return nil
}

// readAccountWithValidation is a wrapper function that adds validation to the readAccount operation.
// It ensures all input parameters are valid before delegating to the actual implementation.
// This pattern is used consistently across all operations to provide robust error handling
// and prevent panics from invalid input parameters.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the storage path and metadata
//   - d: Field data containing request parameters (unused in read operations)
//
// Returns:
//   - *logical.Response: Response containing the account address, or nil if not found
//   - error: Any error encountered during validation or the read operation
func (b *backend) readAccountWithValidation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.validateOperation(ctx, req, d); err != nil {
		return nil, fmt.Errorf("read account validation failed: %w", err)
	}
	return b.readAccount(ctx, req, d)
}

// createAccountWithValidation is a wrapper function that adds validation to the createAccount operation.
// It ensures all input parameters are valid before delegating to the actual implementation.
// This method handles both new account generation and existing account import based on
// the presence of the 'import' field in the request data.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing storage path and metadata
//   - d: Field data containing account ID and optional import key
//
// Returns:
//   - *logical.Response: Response containing the created account's address
//   - error: Any error encountered during validation or account creation
func (b *backend) createAccountWithValidation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.validateOperation(ctx, req, d); err != nil {
		return nil, fmt.Errorf("create account validation failed: %w", err)
	}
	return b.createAccount(ctx, req, d)
}

// updateAccountWithValidation is a wrapper function that adds validation to the updateAccount operation.
// It ensures all input parameters are valid before delegating to the actual implementation.
// Note that this plugin does not support updating existing accounts for security reasons,
// but the operation is provided for framework compatibility.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing storage path and metadata
//   - d: Field data containing request parameters
//
// Returns:
//   - *logical.Response: Always nil as updates are not supported
//   - error: Always returns an "unsupported operation" error after validation
func (b *backend) updateAccountWithValidation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.validateOperation(ctx, req, d); err != nil {
		return nil, fmt.Errorf("update account validation failed: %w", err)
	}
	return b.updateAccount(ctx, req, d)
}

// listAccountIDsWithValidation is a wrapper function that adds validation to the listAccountIDs operation.
// It ensures all input parameters are valid before delegating to the actual implementation.
// This method retrieves all available account identifiers from storage for discovery purposes.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the storage path to list
//   - d: Field data (unused in list operations but validated for consistency)
//
// Returns:
//   - *logical.Response: Response containing the list of account IDs
//   - error: Any error encountered during validation or the list operation
func (b *backend) listAccountIDsWithValidation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.validateOperation(ctx, req, d); err != nil {
		return nil, fmt.Errorf("list accounts validation failed: %w", err)
	}
	return b.listAccountIDs(ctx, req, d)
}

// signWithValidation is a wrapper function that adds validation to the sign operation.
// It ensures all input parameters are valid before delegating to the actual implementation.
// This method handles cryptographic signing operations using stored private keys and
// includes comprehensive validation of both the account ID and data to be signed.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the operation path
//   - d: Field data containing account ID and hex-encoded data to sign
//
// Returns:
//   - *logical.Response: Response containing the hex-encoded signature
//   - error: Any error encountered during validation or the signing operation
func (b *backend) signWithValidation(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := b.validateOperation(ctx, req, d); err != nil {
		return nil, fmt.Errorf("sign operation validation failed: %w", err)
	}
	return b.sign(ctx, req, d)
}

// accountExistenceCheckWithValidation is a wrapper function that adds validation to the accountExistenceCheck operation.
// It ensures all input parameters are valid before delegating to the actual implementation.
// This method is used by the Vault framework to determine whether a CREATE or UPDATE operation
// should be performed based on whether an account already exists at the specified path.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the storage path to check
//   - d: Field data (unused in existence checks but validated for consistency)
//
// Returns:
//   - bool: true if the account exists at the specified path, false otherwise
//   - error: Any error encountered during validation or the existence check
func (b *backend) accountExistenceCheckWithValidation(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	if err := b.validateOperation(ctx, req, d); err != nil {
		return false, fmt.Errorf("account existence check validation failed: %w", err)
	}
	return b.accountExistenceCheck(ctx, req, d)
}
