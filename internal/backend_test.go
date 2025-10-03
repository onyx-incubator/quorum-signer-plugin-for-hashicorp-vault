// Package internal provides tests for the backend implementation of the Quorum signer plugin for HashiCorp Vault.
// This file contains integration tests that verify the correct routing and operation support
// across all configured paths in the backend.
package internal

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

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
