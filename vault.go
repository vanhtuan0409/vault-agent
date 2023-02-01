package vaultagent

import (
	"context"

	vault "github.com/hashicorp/vault/api"
)

func GetVaultClient(ctx context.Context, addr, token string) (*vault.Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = addr
	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}
