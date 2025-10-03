// Package internal provides the backend implementation for the Quorum signer plugin for HashiCorp Vault.
// This package handles account creation, key management, and cryptographic signing operations
// for Ethereum/Quorum blockchain accounts.
package internal

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	geCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Constants for validation and formatting
const (
	// EthereumPrivateKeyLength is the expected length of an Ethereum private key in hex characters (32 bytes = 64 hex chars)
	EthereumPrivateKeyLength = 64
	// HexPrefix is the standard hex prefix used in Ethereum
	HexPrefix = "0x"
	// AddressResponseKey is the key used in responses for account addresses
	AddressResponseKey = "addr"
	// SignatureResponseKey is the key used in responses for signatures
	SignatureResponseKey = "sig"
)

// Regular expressions for input validation
var (
	// hexStringRegex validates that a string contains only valid hexadecimal characters
	hexStringRegex = regexp.MustCompile(`^[0-9a-fA-F]*$`)
)

// hexAccountData represents an Ethereum account with both address and private key
// stored as hex-encoded strings for safe serialization and storage.
type hexAccountData struct {
	// HexAddress is the Ethereum address in hexadecimal format (without 0x prefix)
	HexAddress string
	// HexKey is the private key in hexadecimal format (without 0x prefix)
	HexKey string
}

// updateUnsupportedErr is returned when attempting to update existing account secrets,
// which is not supported by this plugin for security reasons.
var updateUnsupportedErr = errors.New("updating existing secrets is not supported")

// validateRequest performs common validation checks on request parameters
func validateRequest(ctx context.Context, req *logical.Request) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.Storage == nil {
		return fmt.Errorf("storage cannot be nil")
	}
	return nil
}

// validateHexString validates that a string contains only valid hexadecimal characters
func validateHexString(s string) bool {
	return hexStringRegex.MatchString(s)
}

// accountExistenceCheck verifies whether an account exists at the specified storage path.
// This is used by the Vault framework to determine if a CREATE or UPDATE operation
// should be performed. It validates all input parameters and provides detailed error
// context for troubleshooting storage issues.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the storage path and other metadata
//   - _: Field data (unused in this implementation)
//
// Returns:
//   - bool: true if the account exists, false otherwise
//   - error: Any error encountered during the existence check
func (b *backend) accountExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	b.Logger().Info("performing existence check")

	// Validate request using helper function
	if err := validateRequest(ctx, req); err != nil {
		return false, err
	}

	storageEntry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		b.Logger().Error("unable to perform existence check", "path", req.Path, "err", err)
		return false, fmt.Errorf("storage get failed for path %s: %w", req.Path, err)
	}

	exists := storageEntry != nil
	b.Logger().Info("performed existence check", "result", exists)
	return exists, nil
}

// readAccount retrieves an existing account's address from storage at the specified path.
// This function handles the READ operation for account endpoints, returning the
// Ethereum address associated with the account. It includes comprehensive input
// validation and error handling for storage operations.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the storage path
//   - _: Field data (unused in this implementation)
//
// Returns:
//   - *logical.Response: Response containing the account address, or nil if not found
//   - error: Any error encountered during the read operation
func (b *backend) readAccount(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("reading account", "path", req.Path)

	// Validate inputs
	if err := validateRequest(ctx, req); err != nil {
		return nil, err
	}

	storageEntry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read account from storage at path %s: %w", req.Path, err)
	}
	if storageEntry == nil {
		// a nil Response is handled by the Vault server
		return nil, nil
	}

	var hexAddr string
	if err := storageEntry.DecodeJSON(&hexAddr); err != nil {
		return nil, fmt.Errorf("failed to decode account data from storage: %w", err)
	}

	// Validate decoded address is not empty
	if hexAddr == "" {
		return nil, fmt.Errorf("account address is empty in storage")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			AddressResponseKey: hexAddr,
		},
	}, nil
}

// updateAccount handles UPDATE operations on existing accounts by returning an error.
// This plugin does not support updating existing account secrets for security reasons,
// as modifying cryptographic keys could compromise account security and integrity.
//
// Parameters:
//   - _: Context (unused as operation is not supported)
//   - _: Request (unused as operation is not supported)
//   - _: Field data (unused as operation is not supported)
//
// Returns:
//   - *logical.Response: Always nil
//   - error: Always returns updateUnsupportedErr
func (b *backend) updateAccount(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, updateUnsupportedErr
}

// createAccount handles the creation of new Ethereum accounts or import of existing ones.
// This function supports two modes of operation:
//  1. Generate a new random account if no import key is provided
//  2. Import an existing account from a provided private key
//
// The function performs comprehensive validation of all inputs, generates or imports
// the cryptographic key material, and stores both the account address and private key
// in Vault's secure storage with proper error handling throughout.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing storage path and metadata
//   - d: Field data containing optional import key and required account ID
//
// Returns:
//   - *logical.Response: Response containing the created account's address
//   - error: Any error encountered during account creation or import
func (b *backend) createAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Validate inputs using helper function
	if err := validateRequest(ctx, req); err != nil {
		return nil, err
	}
	if d == nil {
		return nil, fmt.Errorf("field data cannot be nil")
	}

	var (
		accountData *hexAccountData
		err         error
	)

	if rawKey, ok := d.GetOk("import"); ok {
		b.Logger().Info("importing existing account", "path", req.Path)
		rawKeyStr, ok := rawKey.(string)
		if !ok {
			return nil, fmt.Errorf("key to import must be a string, got %T", rawKey)
		}
		if strings.TrimSpace(rawKeyStr) == "" {
			return nil, fmt.Errorf("key to import cannot be empty")
		}

		accountData, err = rawKeyToHexAccountData(rawKeyStr)
		if err != nil {
			return nil, fmt.Errorf("unable to import account: %w", err)
		}
	} else {
		b.Logger().Info("creating new account", "path", req.Path)

		accountData, err = generateAccount()
		if err != nil {
			return nil, fmt.Errorf("unable to generate new account: %w", err)
		}
	}

	// Validate generated/imported account data
	if accountData == nil {
		return nil, fmt.Errorf("account data is nil")
	}
	if accountData.HexAddress == "" {
		return nil, fmt.Errorf("generated account address is empty")
	}
	if accountData.HexKey == "" {
		return nil, fmt.Errorf("generated account key is empty")
	}

	addrStorageEntry, err := logical.StorageEntryJSON(req.Path, accountData.HexAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create address storage entry: %w", err)
	}

	acctID, ok := d.GetOk("acctID")
	if !ok {
		return nil, fmt.Errorf("acctID must be provided in path")
	}
	acctIDStr, ok := acctID.(string)
	if !ok {
		return nil, fmt.Errorf("acctID must be a string, got %T", acctID)
	}

	keyStorageEntry, err := logical.StorageEntryJSON(fmt.Sprintf("%v/%v", keyPath, acctIDStr), accountData.HexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, addrStorageEntry); err != nil {
		return nil, fmt.Errorf("unable to store account address at path %s: %w", req.Path, err)
	}
	if err := req.Storage.Put(ctx, keyStorageEntry); err != nil {
		return nil, fmt.Errorf("unable to store account key for acctID %s: %w", acctIDStr, err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			AddressResponseKey: accountData.HexAddress,
		},
	}, nil
}

// generateAccount creates a new random Ethereum account with a cryptographically
// secure private key. This function uses the go-ethereum library's key generation
// functionality to ensure proper entropy and key format compliance.
//
// Returns:
//   - *hexAccountData: The generated account data with address and private key
//   - error: Any error encountered during key generation or conversion
func generateAccount() (*hexAccountData, error) {
	key, err := geCrypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new private key: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("generated private key is nil")
	}

	return keyToHexAccountData(key)
}

// rawKeyToHexAccountData converts a raw private key string into structured account data.
// This function validates the input key format, ensures it meets Ethereum private key
// requirements (64 hex characters representing 32 bytes), and converts it to the
// internal hexAccountData format for storage and use.
//
// The function accepts keys with or without the "0x" prefix and performs comprehensive
// validation to ensure the key is properly formatted before conversion.
//
// Parameters:
//   - rawKey: The raw private key as a hex string (with or without 0x prefix)
//
// Returns:
//   - *hexAccountData: The converted account data with address and private key
//   - error: Any error encountered during validation or conversion
func rawKeyToHexAccountData(rawKey string) (*hexAccountData, error) {
	trimmedRawKey := strings.TrimSpace(rawKey)
	if trimmedRawKey == "" {
		return nil, fmt.Errorf("raw key cannot be empty")
	}

	// Remove hex prefix and validate format
	keyWithoutPrefix := strings.TrimPrefix(trimmedRawKey, HexPrefix)
	if len(keyWithoutPrefix) == 0 {
		return nil, fmt.Errorf("raw key is empty after removing %s prefix", HexPrefix)
	}
	if len(keyWithoutPrefix) != EthereumPrivateKeyLength {
		return nil, fmt.Errorf("raw key must be %d hex characters (32 bytes), got %d characters",
			EthereumPrivateKeyLength, len(keyWithoutPrefix))
	}

	// Validate hex characters
	if !validateHexString(keyWithoutPrefix) {
		return nil, fmt.Errorf("raw key contains invalid hex characters")
	}

	key, err := geCrypto.HexToECDSA(keyWithoutPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to decode raw key from hex: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("decoded private key is nil")
	}

	return keyToHexAccountData(key)
}

// keyToHexAccountData converts an ECDSA private key to hexadecimal account data.
// This function takes a parsed ECDSA private key and generates the corresponding
// Ethereum address, then converts both the key and address to hex string format
// for safe storage and serialization.
//
// The function performs extensive validation to ensure all cryptographic operations
// succeed and that the resulting data is properly formatted and non-empty.
//
// Parameters:
//   - key: The ECDSA private key to convert
//
// Returns:
//   - *hexAccountData: The converted account data with hex-encoded address and key
//   - error: Any error encountered during conversion or validation
func keyToHexAccountData(key *ecdsa.PrivateKey) (*hexAccountData, error) {
	if key == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	publicKey := key.Public()
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	if publicKeyECDSA == nil {
		return nil, fmt.Errorf("public key ECDSA is nil after type assertion")
	}

	addr := geCrypto.PubkeyToAddress(*publicKeyECDSA)

	keyBytes := geCrypto.FromECDSA(key)
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("private key bytes are empty")
	}

	hexKeyEncoded := hexutil.Encode(keyBytes)
	if hexKeyEncoded == "" {
		return nil, fmt.Errorf("failed to encode private key to hex")
	}

	hexKey := strings.TrimPrefix(hexKeyEncoded, HexPrefix)
	if hexKey == "" {
		return nil, fmt.Errorf("private key hex string is empty after removing %s prefix", HexPrefix)
	}

	hexAddress := strings.TrimPrefix(addr.String(), HexPrefix)
	if hexAddress == "" {
		return nil, fmt.Errorf("address hex string is empty after removing %s prefix", HexPrefix)
	}

	return &hexAccountData{
		HexAddress: hexAddress,
		HexKey:     hexKey,
	}, nil
}

// listAccountIDs retrieves a list of all account identifiers stored at the specified path.
// This function handles LIST operations for account endpoints, returning all available
// account IDs that can be used for subsequent operations like reading or signing.
//
// The function includes comprehensive input validation and provides detailed error
// context for troubleshooting storage-related issues.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the storage path to list
//   - _: Field data (unused in this implementation)
//
// Returns:
//   - *logical.Response: Response containing the list of account IDs
//   - error: Any error encountered during the list operation
func (b *backend) listAccountIDs(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("listing account IDs", "path", req.Path)

	// Validate inputs
	if err := validateRequest(ctx, req); err != nil {
		return nil, err
	}

	ids, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to list account IDs from storage at path %s: %w", req.Path, err)
	}

	b.Logger().Info("account IDs retrieved from storage", "IDs", ids)

	return logical.ListResponse(ids), nil
}

// sign performs cryptographic signing of arbitrary data using a specified account's private key.
// This function handles the core signing operation by:
//  1. Validating all input parameters including account ID and data to sign
//  2. Retrieving the private key from secure storage
//  3. Decoding the hex data to be signed
//  4. Performing the ECDSA signature operation
//  5. Returning the signature in hex format
//
// The function includes extensive validation of hex data format, ensures the account
// exists, and provides detailed error context for all failure scenarios. The signing
// operation uses the go-ethereum library's cryptographic functions to ensure
// compatibility with Ethereum and Quorum networks.
//
// Parameters:
//   - ctx: The request context for cancellation and timeouts
//   - req: The logical request containing the operation path
//   - d: Field data containing the account ID and hex data to sign
//
// Returns:
//   - *logical.Response: Response containing the hex-encoded signature
//   - error: Any error encountered during validation, key retrieval, or signing
func (b *backend) sign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("signing some data", "path", req.Path)

	// Validate inputs using helper function
	if err := validateRequest(ctx, req); err != nil {
		return nil, err
	}
	if d == nil {
		return nil, fmt.Errorf("field data cannot be nil")
	}

	acctID, ok := d.GetOk("acctID")
	if !ok {
		return nil, fmt.Errorf("acctID must be provided in path")
	}
	acctIDStr, ok := acctID.(string)
	if !ok {
		return nil, fmt.Errorf("acctID must be a string, got %T", acctID)
	}

	toSign, ok := d.GetOk("sign")
	if !ok {
		return nil, fmt.Errorf("hex-encoded data to sign must be provided with 'sign' field")
	}
	toSignStr, ok := toSign.(string)
	if !ok {
		return nil, fmt.Errorf("data to sign must be a string, got %T", toSign)
	}
	if strings.TrimSpace(toSignStr) == "" {
		return nil, fmt.Errorf("data to sign cannot be empty")
	}

	// Decode and validate the payload
	toSignStrTrimmed := strings.TrimPrefix(toSignStr, HexPrefix)
	if len(toSignStrTrimmed) == 0 {
		return nil, fmt.Errorf("data to sign is empty after removing %s prefix", HexPrefix)
	}
	if len(toSignStrTrimmed)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}

	// Validate hex characters
	if !validateHexString(toSignStrTrimmed) {
		return nil, fmt.Errorf("data to sign contains invalid hex characters")
	}

	toSignBytes, err := hex.DecodeString(toSignStrTrimmed)
	if err != nil {
		return nil, fmt.Errorf("data to sign must be valid hex string: %w", err)
	}
	if len(toSignBytes) == 0 {
		return nil, fmt.Errorf("decoded data to sign is empty")
	}

	// Get the private key from storage (fix variable shadowing by using different name)
	privateKeyPath := fmt.Sprintf("%v/%v", keyPath, acctIDStr)
	storageEntry, err := req.Storage.Get(ctx, privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key from storage at path %s: %w", privateKeyPath, err)
	}
	if storageEntry == nil {
		return nil, fmt.Errorf("account not found for acctID %s", acctIDStr)
	}

	var storedHexKey string
	if err := storageEntry.DecodeJSON(&storedHexKey); err != nil {
		return nil, fmt.Errorf("failed to decode private key from storage: %w", err)
	}
	if storedHexKey == "" {
		return nil, fmt.Errorf("private key is empty in storage")
	}

	b.Logger().Info("retrieved account for signing")

	privateKey, err := geCrypto.HexToECDSA(strings.TrimPrefix(storedHexKey, HexPrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key from hex: %w", err)
	}
	if privateKey == nil {
		return nil, fmt.Errorf("decoded private key is nil")
	}

	signature, err := geCrypto.Sign(toSignBytes, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to sign data: %w", err)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("signature is empty")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			SignatureResponseKey: strings.TrimPrefix(hex.EncodeToString(signature), HexPrefix),
		},
	}, nil
}
