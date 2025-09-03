package internal

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	geCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type hexAccountData struct {
	HexAddress string
	HexKey     string
}

var updateUnsupportedErr = errors.New("updating existing secrets is not supported")

func (b *backend) accountExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	b.Logger().Info("performing existence check")

	got, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		b.Logger().Info("unable to perform existence check", "err", err)
		return false, err
	}

	var exists bool
	if got != nil {
		exists = true
	}
	b.Logger().Info("performed existence check", "result", exists)
	return exists, nil
}

func (b *backend) readAccount(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("reading account", "path", req.Path)

	storageEntry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, err
	}
	if storageEntry == nil {
		// a nil Response is handled by the Vault server
		return nil, nil
	}

	var hexAddr string
	if err := storageEntry.DecodeJSON(&hexAddr); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"addr": hexAddr,
		},
	}, nil
}

func (b *backend) updateAccount(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, updateUnsupportedErr
}

func (b *backend) createAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var (
		hexAccountData *hexAccountData
		err            error
	)

	if rawKey, ok := d.GetOk("import"); ok {
		b.Logger().Info("importing existing account", "path", req.Path)
		rawKeyStr, ok := rawKey.(string)
		if !ok {
			return nil, errors.New("key to import must be a string")
		}

		hexAccountData, err = rawKeyToHexAccountData(rawKeyStr)
		if err != nil {
			return nil, fmt.Errorf("unable to import account: %v", err)
		}
	} else {
		b.Logger().Info("creating new account", "path", req.Path)

		hexAccountData, err = generateAccount()
		if err != nil {
			return nil, fmt.Errorf("unable to generate new account: %v", err)
		}
	}

	addrStorageEntry, err := logical.StorageEntryJSON(req.Path, hexAccountData.HexAddress)
	if err != nil {
		return nil, err
	}

	acctID, ok := d.GetOk("acctID")
	if !ok {
		return nil, errors.New("acctID must be provided in path")
	}
	acctIDStr, ok := acctID.(string)
	if !ok {
		return nil, errors.New("acctID must be a string")
	}
	keyStorageEntry, err := logical.StorageEntryJSON(fmt.Sprintf("%v/%v", keyPath, acctIDStr), hexAccountData.HexKey)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, addrStorageEntry); err != nil {
		return nil, fmt.Errorf("unable to store account address: %v", err)
	}
	if err := req.Storage.Put(ctx, keyStorageEntry); err != nil {
		return nil, fmt.Errorf("unable to store account key: %v", err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{},
	}
	resp.Data["addr"] = hexAccountData.HexAddress

	return resp, nil
}

func generateAccount() (*hexAccountData, error) {
	key, err := geCrypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	return keyToHexAccountData(key)
}

func rawKeyToHexAccountData(rawKey string) (*hexAccountData, error) {
	key, err := geCrypto.HexToECDSA(rawKey)
	if err != nil {
		return nil, err
	}

	return keyToHexAccountData(key)
}

func keyToHexAccountData(key *ecdsa.PrivateKey) (*hexAccountData, error) {
	publicKey := key.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	addr := geCrypto.PubkeyToAddress(*publicKeyECDSA)

	var hexKey = hexutil.Encode(geCrypto.FromECDSA(key))
	if hexKey == "" {
		return nil, errors.New("unable to encode private key to hex string")
	}

	return &hexAccountData{
		HexAddress: addr.String(),
		HexKey:     hexKey,
	}, nil
}

func (b *backend) listAccountIDs(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("listing account IDs", "path", req.Path)

	ids, err := req.Storage.List(ctx, req.Path)
	if err != nil {
		return nil, err
	}

	b.Logger().Info("account IDs retrieved from storage", "IDs", ids)

	return logical.ListResponse(ids), nil
}

func (b *backend) sign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("signing some data", "path", req.Path)

	acctID, ok := d.GetOk("acctID")
	if !ok {
		return nil, errors.New("acctID must be provided in path")
	}
	acctIDStr, ok := acctID.(string)
	if !ok {
		return nil, errors.New("acctID must be a string")
	}

	toSign, ok := d.GetOk("sign")
	if !ok {
		return nil, errors.New("hex-encoded data to sign must be provided with 'sign' field")
	}
	toSignStr, ok := toSign.(string)
	if !ok {
		return nil, errors.New("data to sign must be a string")
	}

	// decode the payload
	toSignStrTrimmed := strings.TrimPrefix(toSignStr, "0x")
	toSignByt, err := hex.DecodeString(toSignStrTrimmed)
	if err != nil {
		return nil, fmt.Errorf("data to sign must be valid hex string: %v", err)
	}

	// get the private key from storage
	storageEntry, err := req.Storage.Get(ctx, fmt.Sprintf("%v/%v", keyPath, acctIDStr))
	if err != nil {
		return nil, err
	}

	hexKey := new(string)
	if err := storageEntry.DecodeJSON(hexKey); err != nil {
		return nil, err
	}

	b.Logger().Info("retrieved account for signing")

	key, err := geCrypto.HexToECDSA(*hexKey)
	if err != nil {
		return nil, err
	}

	sig, err := geCrypto.Sign(toSignByt, key)
	if err != nil {
		return nil, fmt.Errorf("unable to sign data: %v", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"sig": hex.EncodeToString(sig),
		},
	}, nil
}
