package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type ConnectToken struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// ConnectTokenVault is a vault a token is issued for. Permission is "", "r"
// or "w"; empty gives the token the server's own access to the vault.
type ConnectTokenVault struct {
	VaultID    string
	Permission string
}

// CreateConnectToken issues a token for a Connect server and returns it with
// the token's ID. op only shows a token when it is issued.
func (c *Client) CreateConnectToken(ctx context.Context, serverID, name string, vaults []ConnectTokenVault, expiresIn string) (*ConnectToken, string, error) {
	args := []string{"connect", "token", "create", name, "--server", serverID}
	for _, vault := range vaults {
		value := vault.VaultID
		if vault.Permission != "" {
			value += "," + vault.Permission
		}
		args = append(args, "--vault", value)
	}
	if expiresIn != "" {
		args = append(args, "--expires-in", expiresIn)
	}

	output, err := c.runner.Run(ctx, "", args...)
	if err != nil {
		return nil, "", err
	}
	token := strings.TrimSpace(string(output))
	if token == "" {
		return nil, "", fmt.Errorf("op connect token create did not return a token")
	}

	// op prints only the token, so find its ID by name. The caller makes sure
	// the name is unique on the server.
	tokens, err := c.ListConnectTokens(ctx, serverID)
	if err != nil {
		return nil, "", fmt.Errorf("token %q was issued, but the server's tokens could not be listed: %w", name, err)
	}
	for _, t := range ActiveConnectTokens(tokens) {
		if t.Name == name {
			return &t, token, nil
		}
	}
	return nil, "", fmt.Errorf("token %q was issued, but is not in the server's token list", name)
}

// ListConnectTokens lists a server's tokens, including revoked ones.
func (c *Client) ListConnectTokens(ctx context.Context, serverID string) ([]ConnectToken, error) {
	output, err := c.runner.Run(ctx, "", "connect", "token", "list", "--server", serverID, "--format", "json")
	if err != nil {
		return nil, err
	}
	var result []ConnectToken
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("could not parse op connect token list output: %w", err)
	}
	return result, nil
}

// ActiveConnectTokens leaves out revoked tokens, which op connect token list
// also returns.
func ActiveConnectTokens(tokens []ConnectToken) []ConnectToken {
	var result []ConnectToken
	for _, token := range tokens {
		if !strings.EqualFold(token.State, "revoked") {
			result = append(result, token)
		}
	}
	return result
}

func (c *Client) RenameConnectToken(ctx context.Context, serverID, id, name string) error {
	_, err := c.runner.Run(ctx, "", "connect", "token", "edit", id, "--server", serverID, "--name", name)
	return err
}

func (c *Client) DeleteConnectToken(ctx context.Context, serverID, id string) error {
	_, err := c.runner.Run(ctx, "", "connect", "token", "delete", id, "--server", serverID)
	return err
}
