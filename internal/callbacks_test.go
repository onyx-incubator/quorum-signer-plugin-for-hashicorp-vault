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
