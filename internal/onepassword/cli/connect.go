package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CredentialsFileName is the file op writes a new Connect server's credentials to.
const CredentialsFileName = "1password-credentials.json"

type ConnectServer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type Client struct {
	runner Runner
}

func NewClient(runner Runner) *Client {
	return &Client{runner: runner}
}

// CreateConnectServer creates a Connect server with access to vaultIDs and
// returns it with its credentials file. op only writes the credentials file
// when the server is created; it can't be fetched again later.
func (c *Client) CreateConnectServer(ctx context.Context, name string, vaultIDs []string) (*ConnectServer, []byte, error) {
	dir, err := os.MkdirTemp("", "op-connect-")
	if err != nil {
		return nil, nil, fmt.Errorf("could not create a directory for the credentials file: %w", err)
	}
	defer os.RemoveAll(dir)

	args := []string{"connect", "server", "create", name}
	if len(vaultIDs) > 0 {
		args = append(args, "--vaults", strings.Join(vaultIDs, ","))
	}
	output, err := c.runner.Run(ctx, dir, args...)
	if err != nil {
		return nil, nil, err
	}

	id := createdServerID(output)
	if id == "" {
		return nil, nil, fmt.Errorf("op connect server create did not report the new server's UUID")
	}
	credentials, err := os.ReadFile(filepath.Join(dir, CredentialsFileName))
	if err != nil {
		return nil, nil, fmt.Errorf("connect server %s was created, but its credentials file could not be read: %w", id, err)
	}

	server, err := c.GetConnectServer(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("connect server %s was created, but could not be read: %w", id, err)
	}
	return server, credentials, nil
}

var createdServerIDPattern = regexp.MustCompile(`(?m)^UUID:\s+(\S+)\s*$`)

// createdServerID reads the UUID from the output of op connect server create,
// which is either text ("UUID: <id>") or JSON with an "id" field.
func createdServerID(output []byte) string {
	var server ConnectServer
	if json.Unmarshal(output, &server) == nil && server.ID != "" {
		return server.ID
	}
	if match := createdServerIDPattern.FindSubmatch(output); match != nil {
		return string(match[1])
	}
	return ""
}

// GetConnectServer returns the server with the given UUID or name, or an error
// wrapping ErrNotFound.
func (c *Client) GetConnectServer(ctx context.Context, server string) (*ConnectServer, error) {
	output, err := c.runner.Run(ctx, "", "connect", "server", "get", server, "--format", "json")
	if err != nil {
		return nil, err
	}
	var result ConnectServer
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("could not parse op connect server get output: %w", err)
	}
	return &result, nil
}

func (c *Client) ListConnectServers(ctx context.Context) ([]ConnectServer, error) {
	output, err := c.runner.Run(ctx, "", "connect", "server", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var result []ConnectServer
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("could not parse op connect server list output: %w", err)
	}
	return result, nil
}

func (c *Client) RenameConnectServer(ctx context.Context, id, name string) error {
	_, err := c.runner.Run(ctx, "", "connect", "server", "edit", id, "--name", name)
	return err
}

func (c *Client) GrantConnectServerVault(ctx context.Context, id, vaultID string) error {
	_, err := c.runner.Run(ctx, "", "connect", "vault", "grant", "--server", id, "--vault", vaultID)
	return err
}

func (c *Client) RevokeConnectServerVault(ctx context.Context, id, vaultID string) error {
	_, err := c.runner.Run(ctx, "", "connect", "vault", "revoke", "--server", id, "--vault", vaultID)
	return err
}

func (c *Client) DeleteConnectServer(ctx context.Context, id string) error {
	_, err := c.runner.Run(ctx, "", "connect", "server", "delete", id)
	return err
}
