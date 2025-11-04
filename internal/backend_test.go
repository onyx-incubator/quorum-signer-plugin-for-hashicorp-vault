// Package internal provides tests for the backend implementation of the Quorum signer plugin for HashiCorp Vault.
// This file contains integration tests that verify the correct routing and operation support
// across all configured paths in the backend.
package internal

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// TestBackendFactory_ErrorCases tests error handling in BackendFactory
func TestBackendFactory_ErrorCases(t *testing.T) {
	tests := map[string]struct {
		ctx  context.Context
		conf *logical.BackendConfig
	}{
		"nil context": {
			ctx:  nil,
			conf: &logical.BackendConfig{},
		},
		"nil config": {
			ctx:  context.Background(),
			conf: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := BackendFactory(tt.ctx, tt.conf)
			require.Error(t, err)
		})
	}
}

func TestBackendFactory_Success(t *testing.T) {
	b, err := BackendFactory(context.Background(), &logical.BackendConfig{})
	require.NoError(t, err)
	require.NotNil(t, b)

	backend, ok := b.(*backend)
	require.True(t, ok)
	require.NotNil(t, backend.Backend)
}

func TestValidateOperation(t *testing.T) {
	b, err := BackendFactory(context.Background(), &logical.BackendConfig{})
	require.NoError(t, err)
	backend := b.(*backend)

	storage := &logical.InmemStorage{}
	d := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: map[string]*framework.FieldSchema{},
	}

	tests := map[string]struct {
		ctx     context.Context
		req     *logical.Request
		d       *framework.FieldData
		wantErr bool
	}{
		"valid operation": {
			ctx: context.Background(),
			req: &logical.Request{
				Storage: storage,
				Path:    "accounts/test",
			},
			d:       d,
			wantErr: false,
		},
		"nil context": {
			ctx: nil,
			req: &logical.Request{
				Storage: storage,
				Path:    "accounts/test",
			},
			d:       d,
			wantErr: true,
		},
		"nil request": {
			ctx:     context.Background(),
			req:     nil,
			d:       d,
			wantErr: true,
		},
		"nil storage": {
			ctx: context.Background(),
			req: &logical.Request{
				Storage: nil,
				Path:    "accounts/test",
			},
			d:       d,
			wantErr: true,
		},
		"nil field data": {
			ctx: context.Background(),
			req: &logical.Request{
				Storage: storage,
				Path:    "accounts/test",
			},
			d:       nil,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := backend.validateOperation(tt.ctx, tt.req, tt.d)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidationWrappers(t *testing.T) {
	b, err := BackendFactory(context.Background(), &logical.BackendConfig{})
	require.NoError(t, err)
	backend := b.(*backend)

	storage := &logical.InmemStorage{}

	// Test readAccountWithValidation
	t.Run("readAccountWithValidation - nil context", func(t *testing.T) {
		_, err := backend.readAccountWithValidation(nil, &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
	})

	t.Run("readAccountWithValidation - valid", func(t *testing.T) {
		// Store test account
		entry, err := logical.StorageEntryJSON("accounts/test", "testaddr")
		require.NoError(t, err)
		err = storage.Put(context.Background(), entry)
		require.NoError(t, err)

		req := &logical.Request{
			Storage: storage,
			Path:    "accounts/test",
		}
		resp, err := backend.readAccountWithValidation(context.Background(), req, &framework.FieldData{})
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Test createAccountWithValidation
	t.Run("createAccountWithValidation - nil context", func(t *testing.T) {
		_, err := backend.createAccountWithValidation(nil, &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
	})

	// Test updateAccountWithValidation
	t.Run("updateAccountWithValidation - nil context", func(t *testing.T) {
		_, err := backend.updateAccountWithValidation(nil, &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
	})

	t.Run("updateAccountWithValidation - valid but unsupported", func(t *testing.T) {
		_, err := backend.updateAccountWithValidation(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
		require.ErrorIs(t, err, updateUnsupportedErr)
	})

	// Test listAccountIDsWithValidation
	t.Run("listAccountIDsWithValidation - nil context", func(t *testing.T) {
		_, err := backend.listAccountIDsWithValidation(nil, &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
	})

	t.Run("listAccountIDsWithValidation - valid", func(t *testing.T) {
		req := &logical.Request{
			Storage: storage,
			Path:    "accounts/",
		}
		resp, err := backend.listAccountIDsWithValidation(context.Background(), req, &framework.FieldData{})
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	// Test signWithValidation
	t.Run("signWithValidation - nil context", func(t *testing.T) {
		_, err := backend.signWithValidation(nil, &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
	})

	// Test accountExistenceCheckWithValidation
	t.Run("accountExistenceCheckWithValidation - nil context", func(t *testing.T) {
		_, err := backend.accountExistenceCheckWithValidation(nil, &logical.Request{Storage: storage}, &framework.FieldData{})
		require.Error(t, err)
	})

	t.Run("accountExistenceCheckWithValidation - valid", func(t *testing.T) {
		req := &logical.Request{
			Storage: storage,
			Path:    "accounts/test",
		}
		exists, err := backend.accountExistenceCheckWithValidation(context.Background(), req, &framework.FieldData{})
		require.NoError(t, err)
		require.True(t, exists) // Should exist from earlier test
	})
}

func TestAccountIDPath(t *testing.T) {
	b, err := BackendFactory(context.Background(), &logical.BackendConfig{})
	require.NoError(t, err)
	backend := b.(*backend)

	path := backend.accountIDPath()
	require.NotNil(t, path)
	require.NotEmpty(t, path.Pattern)
	require.NotNil(t, path.Fields)
	require.NotNil(t, path.Operations)
	require.NotNil(t, path.ExistenceCheck)

	// Verify required fields
	require.Contains(t, path.Fields, "acctID")
	require.Contains(t, path.Fields, "import")

	// Verify operations exist in the map
	_, hasRead := path.Operations[logical.ReadOperation]
	require.True(t, hasRead, "ReadOperation should be present")
	_, hasCreate := path.Operations[logical.CreateOperation]
	require.True(t, hasCreate, "CreateOperation should be present")
	_, hasUpdate := path.Operations[logical.UpdateOperation]
	require.True(t, hasUpdate, "UpdateOperation should be present")
	_, hasList := path.Operations[logical.ListOperation]
	require.True(t, hasList, "ListOperation should be present")
}

func TestSignPath(t *testing.T) {
	b, err := BackendFactory(context.Background(), &logical.BackendConfig{})
	require.NoError(t, err)
	backend := b.(*backend)

	path := backend.signPath()
	require.NotNil(t, path)
	require.NotEmpty(t, path.Pattern)
	require.NotNil(t, path.Fields)
	require.NotNil(t, path.Operations)

	// Verify required fields
	require.Contains(t, path.Fields, "acctID")
	require.Contains(t, path.Fields, "sign")

	// Verify operations exist in the map
	_, hasRead := path.Operations[logical.ReadOperation]
	require.True(t, hasRead, "ReadOperation should be present")
}

// TestPathRoutingAndSupportedOperations verifies that all configured paths in the backend
// correctly route requests and support their intended operations. This comprehensive test
// ensures that the Vault framework properly maps incoming requests to the appropriate
// handlers based on path patterns and operation types.
//
// The test validates:
//   - Account paths support READ, CREATE, UPDATE, and LIST operations
//   - Signing paths support READ operations for cryptographic signing
//   - Path routing works for both root-level and nested account structures
//   - UPDATE operations correctly return the expected "unsupported" error
//   - Request handling works with proper request data for signing operations
//
// Test Coverage:
//   - Root-level account operations: accounts/mySecret
//   - Root-level account listing: accounts/
//   - Nested account operations: accounts/myApp/appSecret
//   - Nested account listing: accounts/myApp/
//   - Root-level signing: sign/mySecret
//   - Nested signing: sign/myApp/appSecret
//
// Each test case validates that requests are properly routed to the backend handlers
// and that the expected behavior occurs (successful operation or expected error).
// This test serves as a regression test to ensure path configuration changes don't
// break existing functionality.
func TestPathRoutingAndSupportedOperations(t *testing.T) {
	// Create backend instance for testing using the factory function
	b, err := BackendFactory(context.Background(), &logical.BackendConfig{})
	require.NoError(t, err, "failed to create backend")

	// Use in-memory storage for isolated testing
	storage := &logical.InmemStorage{}

	// Test cases covering all path patterns and operations
	tests := []struct {
		// name identifies the test case for debugging and reporting
		name string
		// path is the Vault path being tested (e.g., "accounts/mySecret")
		path string
		// operations is the list of logical operations to test on this path
		operations []logical.Operation
	}{
		{
			name:       "rootpath rw",
			path:       "accounts/mySecret",
			operations: []logical.Operation{logical.ReadOperation, logical.CreateOperation, logical.UpdateOperation},
		},
		{
			name:       "rootpath list",
			path:       "accounts/",
			operations: []logical.Operation{logical.ListOperation},
		},
		{
			name:       "subpath rw",
			path:       "accounts/myApp/appSecret",
			operations: []logical.Operation{logical.ReadOperation, logical.CreateOperation, logical.UpdateOperation},
		},
		{
			name:       "subpath list",
			path:       "accounts/myApp/",
			operations: []logical.Operation{logical.ListOperation},
		},
		{
			name:       "rootpath sign",
			path:       "sign/mySecret",
			operations: []logical.Operation{logical.ReadOperation},
		},
		{
			name:       "subpath sign",
			path:       "sign/myApp/appSecret",
			operations: []logical.Operation{logical.ReadOperation},
		},
	}

	// Execute tests for each path and operation combination
	for _, tt := range tests {
		for _, op := range tt.operations {
			// Generate unique test name combining path description and operation
			testName := fmt.Sprintf("%s_%s", tt.name, op)
			t.Run(testName, func(t *testing.T) {
				// Create logical request for the current test case
				req := &logical.Request{
					Storage:   storage,
					Path:      tt.path,
					Operation: op,
				}

				// Add required request data for signing operations
				// Sign operations require hex-encoded data in the request body
				if strings.HasPrefix(tt.path, "sign/") {
					req.Data = map[string]interface{}{
						"sign": strings.ToLower("7d15728d30727d67a3257e6bbd4724c4d31f830f017fd0e0d2d802c14bdf408d"),
					}
				}

				// Execute the request through the backend
				_, err := b.HandleRequest(context.Background(), req)

				// Validate expected behavior based on operation type
				if logical.UpdateOperation == op {
					// Update operations should return the expected unsupported error
					// This verifies that the operation is routed correctly but properly rejected
					require.ErrorIs(t, err, updateUnsupportedErr)
				} else {
					// All other operations should succeed (though may return empty responses)
					// This validates that path routing and operation handlers work correctly
					require.NoError(t, err)
				}
			})
		}
	}
}
