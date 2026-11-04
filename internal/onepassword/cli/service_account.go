package cli

import (
	"context"
	"errors"
	"strings"
)

// ServiceAccountVault is a vault a service account gets access to, with op's
// permission names: read_items, write_items and share_items.
type ServiceAccountVault struct {
	VaultID     string
	Permissions []string
}

// CreateServiceAccount creates a service account and returns its token. op
// shows the token only here, and has no command to read, change or delete a
// service account: that is only possible in the 1Password web interface.
func (c *Client) CreateServiceAccount(ctx context.Context, name string, vaults []ServiceAccountVault, canCreateVaults bool, expiresIn string) (string, error) {
	args := []string{"service-account", "create", name, "--raw"}
	for _, vault := range vaults {
		value := vault.VaultID
		if len(vault.Permissions) > 0 {
			value += ":" + strings.Join(vault.Permissions, ",")
		}
		args = append(args, "--vault", value)
	}
	if canCreateVaults {
		args = append(args, "--can-create-vaults")
	}
	if expiresIn != "" {
		args = append(args, "--expires-in", expiresIn)
	}

	output, err := c.runner.Run(ctx, "", args...)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(output))
	if !strings.HasPrefix(token, "ops_") {
		// Leave the output out: it may hold the token in another format.
		return "", errors.New("op service-account create did not return a service account token")
	}
	return token, nil
}
