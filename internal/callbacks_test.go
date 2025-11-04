package internal

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"

	geCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func createBackend(t *testing.T) *backend {
	t.Helper()

	conf := logical.TestBackendConfig()

	b, err := BackendFactory(context.Background(), conf)
	require.NoError(t, err, "failed to create backend")
	require.NotNil(t, b, "expected non-nil backend")

	return b.(*backend)
}

func TestAccountExistenceCheck(t *testing.T) {
	b := createBackend(t)

	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON("accounts/myAcct", "96093cadd4bceb60ebdda5b875f5825ef1e91a8e")
	require.NoError(t, err, "failed to create storage entry")

	err = storage.Put(context.Background(), entry)
	require.NoError(t, err, "failed to put storage entry")

	tests := map[string]struct {
		req  *logical.Request
		want bool
	}{
		"exists": {
			req: &logical.Request{
				Storage: storage,
				Path:    "accounts/myAcct",
			},
			want: true,
		},
		"does not exist": {
			req: &logical.Request{
				Storage: &logical.InmemStorage{},
				Path:    "accounts/does-not-exist",
			},
			want: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := b.accountExistenceCheck(context.Background(), tt.req, nil)
			require.NoError(t, err, "unexpected error from existence check")
			require.Equal(t, tt.want, got)
		})
	}
}

func TestReadAccount(t *testing.T) {
	b := createBackend(t)

	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON("accounts/myAcct", "96093cadd4bceb60ebdda5b875f5825ef1e91a8e")
	require.NoError(t, err, "failed to create storage entry")

	err = storage.Put(context.Background(), entry)
	require.NoError(t, err, "failed to put storage entry")

	req := &logical.Request{
		Storage: storage,
		Path:    "accounts/myAcct",
	}

	resp, err := b.readAccount(context.Background(), req, nil)
	require.NoError(t, err, "unexpected error from readAccount")
	require.Equal(t, "96093cadd4bceb60ebdda5b875f5825ef1e91a8e", resp.Data["addr"].(string), "unexpected address in response")
}

func TestReadAccount_AccountNotFound(t *testing.T) {
	b := createBackend(t)

	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage: storage,
		Path:    "accounts/myAcct",
	}

	resp, err := b.readAccount(context.Background(), req, nil)
	require.NoError(t, err, "unexpected error from readAccount")
	require.Nil(t, resp, "expected nil response for non-existent account")
}

func TestUpdateAccount(t *testing.T) {
	b := createBackend(t)

	_, err := b.updateAccount(nil, nil, nil)
	require.Error(t, err, "expected error from updateAccount")
	require.EqualError(t, updateUnsupportedErr, err.Error())
}

func TestCreateAccount_CreateNew(t *testing.T) {
	b := createBackend(t)

	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage: storage,
		Path:    "accounts/myAcct",
	}

	d := &framework.FieldData{
		Raw: map[string]interface{}{
			"acctID": "myAcct",
		},
		Schema: map[string]*framework.FieldSchema{
			"acctID": {
				Type: framework.TypeString,
			},
		},
	}

	resp, err := b.createAccount(context.Background(), req, d)
	require.NoError(t, err, "unexpected error from createAccount")

	// addr in response
	respAddr := strings.TrimPrefix(strings.ToLower(resp.Data["addr"].(string)), "0x")
	require.NotEmpty(t, respAddr, "expected non-empty address in response")

	addrByt, err := hex.DecodeString(respAddr)
	require.NoError(t, err, "address in response is not valid hex")
	require.Len(t, addrByt, 20, "address in response is not 20 bytes")

	// addr stored in vault
	addrSE, err := storage.Get(context.Background(), "accounts/myAcct")
	require.NoError(t, err, "expected address to be stored in vault")

	var storedAddr string
	err = addrSE.DecodeJSON(&storedAddr)
	storedAddr = strings.TrimPrefix(strings.ToLower(storedAddr), "0x")
	require.NoError(t, err, "failed to decode stored address")

	require.Equal(t, respAddr, storedAddr, "address in response does not match address stored in vault")

	// key stored separately in vault
	keySE, err := storage.Get(context.Background(), "keys/myAcct")
	require.NoError(t, err, "expected key to be stored in vault")

	var storedKey string
	err = keySE.DecodeJSON(&storedKey)
	require.NoError(t, err, "failed to decode stored key")

	key, err := geCrypto.HexToECDSA(strings.ToLower(strings.TrimPrefix(storedKey, "0x")))
	require.NoError(t, err, "invalid private key stored in vault")

	publicKey := key.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "cannot assert type: publicKey is not of type *ecdsa.PublicKey")

	addrFromKey := geCrypto.PubkeyToAddress(*publicKeyECDSA)
	require.NotNil(t, addrFromKey, "unable to derive address from private key")

	hexAddressFromKey := strings.ToLower(hex.EncodeToString(addrFromKey.Bytes()))
	require.Equal(t, respAddr, hexAddressFromKey, "address derived from private key does not match address in response")
}

func TestCreateAccount_ImportExisting(t *testing.T) {
	toImport := strings.ToLower("a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec")
	wantAddr := strings.ToLower("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	b := createBackend(t)

	storage := &logical.InmemStorage{}

	req := &logical.Request{
		Storage: storage,
		Path:    "accounts/myAcct",
	}

	d := &framework.FieldData{
		Raw: map[string]interface{}{
			"acctID": "myAcct",
			"import": toImport,
		},
		Schema: map[string]*framework.FieldSchema{
			"acctID": {
				Type: framework.TypeString,
			},
			"import": {
				Type: framework.TypeString,
			},
		},
	}

	resp, err := b.createAccount(context.Background(), req, d)
	require.NoError(t, err, "unexpected error from createAccount")

	// addr in response
	respAddr := strings.TrimPrefix(strings.ToLower(resp.Data["addr"].(string)), "0x")
	require.NotEmpty(t, respAddr, "expected non-empty address in response")
	require.Equal(t, wantAddr, respAddr, "imported address does not match expected address")

	// addr stored in vault
	addrSE, err := storage.Get(context.Background(), "accounts/myAcct")
	require.NoError(t, err, "expected address to be stored in vault")

	var storedAddr string
	err = addrSE.DecodeJSON(&storedAddr)
	storedAddr = strings.TrimPrefix(strings.ToLower(storedAddr), "0x")
	require.NoError(t, err, "failed to decode stored address")

	require.Equal(t, respAddr, storedAddr)

	// key stored separately in vault
	keySE, err := storage.Get(context.Background(), "keys/myAcct")
	require.NoError(t, err, "expected key to be stored in vault")

	var storedKey string
	err = keySE.DecodeJSON(&storedKey)
	require.NoError(t, err, "failed to decode stored key")
	require.Equal(t, toImport, strings.ToLower(storedKey), "imported key does not match stored key")
}

func TestListAccountIDs(t *testing.T) {
	b := createBackend(t)

	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON("accounts/myAcct", "96093cadd4bceb60ebdda5b875f5825ef1e91a8e")
	require.NoError(t, err, "failed to create storage entry")

	err = storage.Put(context.Background(), entry)
	require.NoError(t, err, "failed to put storage entry")

	entry, err = logical.StorageEntryJSON("accounts/anotherAcct", "96093cadd4bceb60ebdda5b875f5825ef1e91a8e")
	require.NoError(t, err, "failed to create storage entry")

	err = storage.Put(context.Background(), entry)
	require.NoError(t, err, "failed to put storage entry")

	req := &logical.Request{
		Storage: storage,
		Path:    "accounts/",
	}

	resp, err := b.listAccountIDs(context.Background(), req, nil)
	require.NoError(t, err, "unexpected error from listAccountIDs")
	ids := resp.Data["keys"].([]string)
	require.Len(t, ids, 2, "expected two account IDs in response")
	require.Contains(t, ids, "myAcct", "expected account ID 'myAcct' in response")
	require.Contains(t, ids, "anotherAcct", "expected account ID 'anotherAcct' in response")
}

func TestSign(t *testing.T) {
	b := createBackend(t)

	key := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	toSign := "bc4c915d69896b198f0292a72373a2bdcd0d52bccbfcec11d9c84c0fff71b0bc"
	wantSig := "f68df2227e39c9ba87baea5966f0c502b038031b10a39e96a721cd270700362d54bae75dcf035a180c17a3a8cf760bfa91a0a41969c0a1630ba6d20e06aa1a8501"

	storage := &logical.InmemStorage{}

	entry, err := logical.StorageEntryJSON("keys/myAcct", key)
	require.NoError(t, err, "failed to create storage entry")

	err = storage.Put(context.Background(), entry)
	require.NoError(t, err, "failed to put storage entry")

	req := &logical.Request{
		Storage: storage,
		Path:    "sign/myAcct",
	}

	d := &framework.FieldData{
		Raw: map[string]interface{}{
			"acctID": "myAcct",
			"sign":   toSign,
		},
		Schema: map[string]*framework.FieldSchema{
			"acctID": {
				Type: framework.TypeString,
			},
			"sign": {
				Type: framework.TypeString,
			},
		},
	}

	resp, err := b.sign(context.Background(), req, d)
	require.NoError(t, err, "unexpected error from sign")
	require.Equal(t, wantSig, resp.Data["sig"], "signature does not match expected value")
}

// Additional test cases for better coverage

func TestAccountExistenceCheck_ErrorCases(t *testing.T) {
	b := createBackend(t)

	t.Run("nil context", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		_, err := b.accountExistenceCheck(nil, req, nil)
		require.Error(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := b.accountExistenceCheck(context.Background(), nil, nil)
		require.Error(t, err)
	})

	t.Run("nil storage", func(t *testing.T) {
		req := &logical.Request{
			Storage: nil,
			Path:    "accounts/test",
		}
		_, err := b.accountExistenceCheck(context.Background(), req, nil)
		require.Error(t, err)
	})
}

func TestReadAccount_ErrorCases(t *testing.T) {
	b := createBackend(t)

	t.Run("nil context", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		_, err := b.readAccount(nil, req, nil)
		require.Error(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := b.readAccount(context.Background(), nil, nil)
		require.Error(t, err)
	})

	t.Run("nil storage", func(t *testing.T) {
		req := &logical.Request{
			Storage: nil,
			Path:    "accounts/test",
		}
		_, err := b.readAccount(context.Background(), req, nil)
		require.Error(t, err)
	})

	t.Run("invalid json data", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		entry := &logical.StorageEntry{
			Key:   "accounts/test",
			Value: []byte("invalid json"),
		}
		err := storage.Put(context.Background(), entry)
		require.NoError(t, err)

		req := &logical.Request{
			Storage: storage,
			Path:    "accounts/test",
		}
		_, err = b.readAccount(context.Background(), req, nil)
		require.Error(t, err)
	})

	t.Run("empty address", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		entry, err := logical.StorageEntryJSON("accounts/test", "")
		require.NoError(t, err)
		err = storage.Put(context.Background(), entry)
		require.NoError(t, err)

		req := &logical.Request{
			Storage: storage,
			Path:    "accounts/test",
		}
		_, err = b.readAccount(context.Background(), req, nil)
		require.Error(t, err)
	})
}

func TestCreateAccount_ErrorCases(t *testing.T) {
	b := createBackend(t)

	t.Run("nil context", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
			},
		}
		_, err := b.createAccount(nil, req, d)
		require.Error(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		d := &framework.FieldData{}
		_, err := b.createAccount(context.Background(), nil, d)
		require.Error(t, err)
	})

	t.Run("nil field data", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		_, err := b.createAccount(context.Background(), req, nil)
		require.Error(t, err)
	})

	t.Run("empty import key", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"import": "   ",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"import": {Type: framework.TypeString},
			},
		}
		_, err := b.createAccount(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("invalid import key", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"import": "invalid",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"import": {Type: framework.TypeString},
			},
		}
		_, err := b.createAccount(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("missing acctID", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
			},
		}
		_, err := b.createAccount(context.Background(), req, d)
		require.Error(t, err)
	})
}

func TestSign_ErrorCases(t *testing.T) {
	b := createBackend(t)

	t.Run("nil context", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{}
		_, err := b.sign(nil, req, d)
		require.Error(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		d := &framework.FieldData{}
		_, err := b.sign(context.Background(), nil, d)
		require.Error(t, err)
	})

	t.Run("nil field data", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		_, err := b.sign(context.Background(), req, nil)
		require.Error(t, err)
	})

	t.Run("missing acctID", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"sign": "deadbeef",
			},
			Schema: map[string]*framework.FieldSchema{
				"sign": {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("missing sign data", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("empty sign data", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "   ",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("only 0x prefix", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "0x",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("odd length hex", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "abc",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("invalid hex characters", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "gggggggg",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("account not found", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "deadbeef",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err := b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("invalid key in storage", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		entry, err := logical.StorageEntryJSON("keys/test", "invalid")
		require.NoError(t, err)
		err = storage.Put(context.Background(), entry)
		require.NoError(t, err)

		req := &logical.Request{
			Storage: storage,
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "deadbeef",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err = b.sign(context.Background(), req, d)
		require.Error(t, err)
	})

	t.Run("empty key in storage", func(t *testing.T) {
		storage := &logical.InmemStorage{}
		entry, err := logical.StorageEntryJSON("keys/test", "")
		require.NoError(t, err)
		err = storage.Put(context.Background(), entry)
		require.NoError(t, err)

		req := &logical.Request{
			Storage: storage,
			Path:    "sign/test",
		}
		d := &framework.FieldData{
			Raw: map[string]interface{}{
				"acctID": "test",
				"sign":   "deadbeef",
			},
			Schema: map[string]*framework.FieldSchema{
				"acctID": {Type: framework.TypeString},
				"sign":   {Type: framework.TypeString},
			},
		}
		_, err = b.sign(context.Background(), req, d)
		require.Error(t, err)
	})
}

func TestListAccountIDs_ErrorCases(t *testing.T) {
	b := createBackend(t)

	t.Run("nil context", func(t *testing.T) {
		req := &logical.Request{
			Storage: &logical.InmemStorage{},
			Path:    "accounts/",
		}
		_, err := b.listAccountIDs(nil, req, nil)
		require.Error(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := b.listAccountIDs(context.Background(), nil, nil)
		require.Error(t, err)
	})

	t.Run("nil storage", func(t *testing.T) {
		req := &logical.Request{
			Storage: nil,
			Path:    "accounts/",
		}
		_, err := b.listAccountIDs(context.Background(), req, nil)
		require.Error(t, err)
	})
}

func TestGenerateAccount(t *testing.T) {
	accountData, err := generateAccount()
	require.NoError(t, err)
	require.NotNil(t, accountData)
	require.NotEmpty(t, accountData.HexAddress)
	require.NotEmpty(t, accountData.HexKey)
	require.Len(t, accountData.HexKey, EthereumPrivateKeyLength)
}

func TestRawKeyToHexAccountData_ErrorCases(t *testing.T) {
	tests := map[string]struct {
		input   string
		wantErr bool
	}{
		"empty string": {
			input:   "",
			wantErr: true,
		},
		"whitespace only": {
			input:   "   ",
			wantErr: true,
		},
		"only 0x prefix": {
			input:   "0x",
			wantErr: true,
		},
		"too short": {
			input:   "abc123",
			wantErr: true,
		},
		"too long": {
			input:   "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eeca0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			wantErr: true,
		},
		"invalid hex characters": {
			input:   "z0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			wantErr: true,
		},
		"valid key without 0x": {
			input:   "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			wantErr: false,
		},
		"valid key with 0x": {
			input:   "0xa0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec",
			wantErr: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := rawKeyToHexAccountData(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

func TestKeyToHexAccountData_ErrorCases(t *testing.T) {
	t.Run("nil key", func(t *testing.T) {
		result, err := keyToHexAccountData(nil)
		require.Error(t, err)
		require.Nil(t, result)
	})

	t.Run("valid key", func(t *testing.T) {
		key, err := geCrypto.GenerateKey()
		require.NoError(t, err)

		result, err := keyToHexAccountData(key)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.HexAddress)
		require.NotEmpty(t, result.HexKey)
	})
}

func TestValidateRequest(t *testing.T) {
	tests := map[string]struct {
		ctx     context.Context
		req     *logical.Request
		wantErr bool
	}{
		"valid request": {
			ctx: context.Background(),
			req: &logical.Request{
				Storage: &logical.InmemStorage{},
			},
			wantErr: false,
		},
		"nil context": {
			ctx: nil,
			req: &logical.Request{
				Storage: &logical.InmemStorage{},
			},
			wantErr: true,
		},
		"nil request": {
			ctx:     context.Background(),
			req:     nil,
			wantErr: true,
		},
		"nil storage": {
			ctx: context.Background(),
			req: &logical.Request{
				Storage: nil,
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateRequest(tt.ctx, tt.req)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateHexString(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"valid hex lowercase":    {input: "deadbeef", want: true},
		"valid hex uppercase":    {input: "DEADBEEF", want: true},
		"valid hex mixed":        {input: "DeAdBeEf", want: true},
		"valid hex with numbers": {input: "a1b2c3d4", want: true},
		"empty string":           {input: "", want: true},
		"invalid with g":         {input: "deadbeeg", want: false},
		"invalid with space":     {input: "dead beef", want: false},
		"invalid with 0x":        {input: "0xdeadbeef", want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := validateHexString(tt.input)
			require.Equal(t, tt.want, result)
		})
	}
}

func TestCreateAccount_WithHexPrefix(t *testing.T) {
	b := createBackend(t)

	storage := &logical.InmemStorage{}

	toImport := "0xa0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	wantAddr := strings.ToLower("4d6d744b6da435b5bbdde2526dc20e9a41cb72e5")

	req := &logical.Request{
		Storage: storage,
		Path:    "accounts/myAcct",
	}

	d := &framework.FieldData{
		Raw: map[string]interface{}{
			"acctID": "myAcct",
			"import": toImport,
		},
		Schema: map[string]*framework.FieldSchema{
			"acctID": {Type: framework.TypeString},
			"import": {Type: framework.TypeString},
		},
	}

	resp, err := b.createAccount(context.Background(), req, d)
	require.NoError(t, err)
	require.Equal(t, wantAddr, strings.ToLower(resp.Data["addr"].(string)))
}

func TestSign_WithHexPrefix(t *testing.T) {
	b := createBackend(t)

	key := "a0379af19f0b55b0f384f83c95f668ba600b78f487f6414f2d22339273891eec"
	toSign := "0xbc4c915d69896b198f0292a72373a2bdcd0d52bccbfcec11d9c84c0fff71b0bc"
	wantSig := "f68df2227e39c9ba87baea5966f0c502b038031b10a39e96a721cd270700362d54bae75dcf035a180c17a3a8cf760bfa91a0a41969c0a1630ba6d20e06aa1a8501"

	storage := &logical.InmemStorage{}

	entry, err := logical.StorageEntryJSON("keys/myAcct", key)
	require.NoError(t, err)

	err = storage.Put(context.Background(), entry)
	require.NoError(t, err)

	req := &logical.Request{
		Storage: storage,
		Path:    "sign/myAcct",
	}

	d := &framework.FieldData{
		Raw: map[string]interface{}{
			"acctID": "myAcct",
			"sign":   toSign,
		},
		Schema: map[string]*framework.FieldSchema{
			"acctID": {Type: framework.TypeString},
			"sign":   {Type: framework.TypeString},
		},
	}

	resp, err := b.sign(context.Background(), req, d)
	require.NoError(t, err)
	require.Equal(t, wantSig, resp.Data["sig"])
}
