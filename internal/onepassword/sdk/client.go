package sdk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	sdk "github.com/1password/onepassword-sdk-go"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/util"
)

type Client struct {
	sdkClient *sdk.Client
	config    SDKConfig
	groups    groupCache
}

type SDKConfig struct {
	ProviderUserAgent   string
	ServiceAccountToken string
	Account             string
}

func (c *Client) GetVault(ctx context.Context, uuid string) (*model.Vault, error) {
	vault, err := c.sdkClient.Vaults().GetOverview(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault using sdk: %w", err)
	}

	v := &model.Vault{}
	v.FromSDKVault(&vault)

	return v, nil
}

func (c *Client) GetVaultsByTitle(ctx context.Context, title string) ([]model.Vault, error) {
	decryptDetails := true
	vaultList, err := c.sdkClient.Vaults().List(ctx, sdk.VaultListParams{DecryptDetails: &decryptDetails})
	if err != nil {
		return nil, fmt.Errorf("failed to get vaults using sdk: %w", err)
	}

	var result []model.Vault
	for _, vault := range vaultList {
		if vault.Title == title {
			var modelVault model.Vault
			modelVault.FromSDKVault(&vault)
			result = append(result, modelVault)
		}
	}

	return result, nil
}

func (c *Client) GetVaultDetails(ctx context.Context, uuid string) (*model.Vault, error) {
	includeAccessors := true
	vault, err := c.sdkClient.Vaults().Get(ctx, uuid, sdk.VaultGetParams{Accessors: &includeAccessors})
	if err != nil {
		return nil, c.withServiceAccountVaultHint(
			fmt.Errorf("failed to get vault details using sdk: %w", err),
			"this service account can only access vaults assigned to it or created by it, and cannot manage a vault created using desktop authentication or another principal",
		)
	}

	result := &model.Vault{}
	result.FromSDKVaultDetails(&vault)
	return result, nil
}

func (c *Client) CreateVault(ctx context.Context, vault *model.Vault, allowAdminsAccess bool) (*model.Vault, error) {
	created, err := c.sdkClient.Vaults().Create(ctx, vault.ToSDKCreateParams(allowAdminsAccess))
	if err != nil {
		return nil, c.withServiceAccountVaultHint(
			fmt.Errorf("failed to create vault using sdk: %w", err),
			"the service account must have permission to create vaults",
		)
	}

	result := &model.Vault{}
	result.FromSDKVaultDetails(&created)
	return result, nil
}

func (c *Client) UpdateVault(ctx context.Context, vault *model.Vault) (*model.Vault, error) {
	updated, err := c.sdkClient.Vaults().Update(ctx, vault.ID, vault.ToSDKUpdateParams())
	if err != nil {
		return nil, c.withServiceAccountVaultHint(
			fmt.Errorf("failed to update vault using sdk: %w", err),
			"service accounts cannot update vault metadata",
		)
	}

	result := &model.Vault{}
	result.FromSDKVaultDetails(&updated)
	return result, nil
}

func (c *Client) DeleteVault(ctx context.Context, uuid string) error {
	if err := c.sdkClient.Vaults().Delete(ctx, uuid); err != nil {
		return c.withServiceAccountVaultHint(
			fmt.Errorf("failed to delete vault using sdk: %w", err),
			"service accounts can only delete vaults they created",
		)
	}
	return nil
}

func (c *Client) GrantVaultGroupPermissions(ctx context.Context, uuid string, access []model.VaultGroupAccess) error {
	groupAccess := make([]sdk.GroupAccess, len(access))
	for i, permission := range access {
		groupAccess[i] = sdk.GroupAccess{
			GroupID:     permission.GroupID,
			Permissions: permission.Permissions,
		}
	}
	if err := c.sdkClient.Vaults().GrantGroupPermissions(ctx, uuid, groupAccess); err != nil {
		return c.withServiceAccountVaultHint(
			fmt.Errorf("failed to grant vault group permissions using sdk: %w", err),
			"service accounts can only manage permissions for vaults they created",
		)
	}
	return nil
}

func (c *Client) UpdateVaultGroupPermissions(ctx context.Context, uuid string, access []model.VaultGroupAccess) error {
	groupAccess := make([]sdk.GroupVaultAccess, len(access))
	for i, permission := range access {
		groupAccess[i] = sdk.GroupVaultAccess{
			VaultID:     uuid,
			GroupID:     permission.GroupID,
			Permissions: permission.Permissions,
		}
	}
	if err := c.sdkClient.Vaults().UpdateGroupPermissions(ctx, groupAccess); err != nil {
		return c.withServiceAccountVaultHint(
			fmt.Errorf("failed to update vault group permissions using sdk: %w", err),
			"service accounts can only manage permissions for vaults they created",
		)
	}
	return nil
}

func (c *Client) RevokeVaultGroupPermission(ctx context.Context, uuid, groupID string) error {
	if err := c.sdkClient.Vaults().RevokeGroupPermissions(ctx, uuid, groupID); err != nil {
		return c.withServiceAccountVaultHint(
			fmt.Errorf("failed to revoke vault group permissions using sdk: %w", err),
			"service accounts can only manage permissions for vaults they created",
		)
	}
	return nil
}

func (c *Client) withServiceAccountVaultHint(err error, limitation string) error {
	if c.config.ServiceAccountToken == "" {
		return err
	}
	return fmt.Errorf("%w. Service account limitation: %s", err, limitation)
}

// GetItem looks up an item by UUID or by title.
// If itemUuid is a valid UUID format, it attempts to fetch the item by UUID.
// If itemUuid is not a valid UUID format, it treats the parameter as a title
// and looks up the item by title instead.
func (c *Client) GetItem(ctx context.Context, itemUuid, vaultUuid string) (*model.Item, error) {
	// Resolve vault name to UUID if needed
	resolvedVaultUUID, err := c.resolveVaultUUID(ctx, vaultUuid)
	if err != nil {
		return nil, err
	}

	if util.IsValidUUID(itemUuid) {
		// Valid UUID, use GetItem directly
		sdkItem, err := c.sdkClient.Items().Get(ctx, resolvedVaultUUID, itemUuid)
		if err != nil {
			return nil, fmt.Errorf("failed to get item using sdk: %w", err)
		}

		modelItem := &model.Item{}
		err = modelItem.FromSDKItemToModel(&sdkItem)
		if err != nil {
			return nil, fmt.Errorf("sdk.GetItem failed to convert item using sdk: %w", err)
		}
		return modelItem, nil
	}

	// Not a UUID, use GetItemByTitle
	return c.GetItemByTitle(ctx, itemUuid, resolvedVaultUUID)
}

func (c *Client) GetItemByTitle(ctx context.Context, title string, vaultUuid string) (*model.Item, error) {
	// Resolve vault name to UUID if needed
	resolvedVaultUUID, err := c.resolveVaultUUID(ctx, vaultUuid)
	if err != nil {
		return nil, err
	}

	items, err := c.sdkClient.Items().List(ctx, resolvedVaultUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item using sdk: %w", err)
	}

	var matchedID string
	var count int

	for _, item := range items {
		if item.Title == title {
			matchedID = item.ID
			count++
		}
	}

	if count != 1 {
		return nil, fmt.Errorf("found %d item(s) in vault %q with title %q", count, vaultUuid, title)
	}

	sdkItem, err := c.sdkClient.Items().Get(ctx, resolvedVaultUUID, matchedID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item using sdk: %w", err)
	}

	modelItem := &model.Item{}
	err = modelItem.FromSDKItemToModel(&sdkItem)
	if err != nil {
		return nil, fmt.Errorf("sdk.GetItemByTitle failed to convert item using sdk: %w", err)
	}

	return modelItem, nil
}

func (c *Client) CreateItem(ctx context.Context, item *model.Item, vaultUuid string) (*model.Item, error) {
	params := item.FromModelItemToSDKCreateParams()

	if params.VaultID != vaultUuid {
		return nil, fmt.Errorf("vault UUID mismatch: item has %s but %s was provided", params.VaultID, vaultUuid)
	}

	var sdkItem sdk.Item
	err := util.RetryOnConflict(ctx, func() error {
		var createErr error
		sdkItem, createErr = c.sdkClient.Items().Create(ctx, params)
		return createErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create item using sdk: %w", err)
	}

	modelItem := &model.Item{}
	err = modelItem.FromSDKItemToModel(&sdkItem)
	if err != nil {
		return nil, fmt.Errorf("sdk.CreateItem failed to convert item using sdk: %w", err)
	}
	return modelItem, nil
}

func (c *Client) UpdateItem(ctx context.Context, item *model.Item, vaultUuid string) (*model.Item, error) {
	currentItem, err := c.sdkClient.Items().Get(ctx, vaultUuid, item.ID)
	if err != nil {
		return nil, err
	}

	params := item.FromModelItemToSDKCreateParams()
	currentItem.Title = params.Title
	currentItem.Category = params.Category
	currentItem.Fields = params.Fields
	currentItem.Sections = params.Sections
	currentItem.Tags = params.Tags
	currentItem.Websites = params.Websites
	if params.Notes != nil {
		currentItem.Notes = *params.Notes
	}

	var updatedItem sdk.Item
	err = util.RetryOnConflict(ctx, func() error {
		var updateErr error
		updatedItem, updateErr = c.sdkClient.Items().Put(ctx, currentItem)
		return updateErr
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update item using sdk: %w", err)
	}

	// Convert back to provider model
	modelItem := &model.Item{}
	err = modelItem.FromSDKItemToModel(&updatedItem)
	if err != nil {
		return nil, fmt.Errorf("sdk.UpdateItem failed to convert item using sdk: %w", err)
	}
	return modelItem, nil
}

func (c *Client) DeleteItem(ctx context.Context, item *model.Item, vaultUuid string) error {
	err := util.RetryOnConflict(ctx, func() error {
		return c.sdkClient.Items().Delete(ctx, vaultUuid, item.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to delete item using sdk: %w", err)
	}

	return nil
}

func (c *Client) GetFileContent(ctx context.Context, file *model.ItemFile, itemUUID, vaultUUID string) ([]byte, error) {
	fileAttributes := sdk.FileAttributes{
		Name: file.Name,
		ID:   file.ID,
		Size: uint32(file.Size),
	}

	content, err := c.sdkClient.Items().Files().Read(ctx, vaultUUID, itemUUID, fileAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to read file using sdk: %w", err)
	}

	return content, nil
}

// GetEnvironmentVariables reads environment variables from a 1Password Environment.
func (c *Client) GetEnvironmentVariables(ctx context.Context, environmentID string) ([]model.EnvironmentVariable, error) {
	res, err := c.sdkClient.Environments().GetVariables(ctx, environmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment variables using sdk: %w", err)
	}

	result := make([]model.EnvironmentVariable, len(res.Variables))
	for i, v := range res.Variables {
		result[i] = model.EnvironmentVariable{
			Name:   v.Name,
			Value:  v.Value,
			Masked: v.Masked,
		}
	}
	return result, nil
}

func (c *Client) GetGroup(ctx context.Context, uuid string) (*model.Group, error) {
	group, err := c.sdkClient.Groups().Get(ctx, uuid, sdk.GroupGetParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to get group using sdk: %w", err)
	}

	result := &model.Group{}
	result.FromSDKGroup(&group)
	return result, nil
}

// GetGroupsByName finds groups by name. The SDK cannot list groups, so it
// compares the names of the groups that have access to the vaults the caller
// can see. A group without access to any of those vaults is not found.
func (c *Client) GetGroupsByName(ctx context.Context, name string) ([]model.Group, error) {
	return c.groups.byName(ctx, name, func(ctx context.Context) ([]model.Group, error) {
		vaults, err := c.sdkClient.Vaults().List(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list vaults using sdk: %w", err)
		}

		vaultIDs := make([]string, len(vaults))
		for i, vault := range vaults {
			vaultIDs[i] = vault.ID
		}
		return collectGroups(ctx, vaultIDs, c.vaultGroupIDs, c.GetGroup)
	})
}

// groupCache keeps the groups found by one scan of the vaults, so that every
// lookup by name in a run shares a single scan.
type groupCache struct {
	mu     sync.Mutex
	loaded bool
	groups []model.Group
}

func (c *groupCache) byName(ctx context.Context, name string, load func(ctx context.Context) ([]model.Group, error)) ([]model.Group, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loaded {
		groups, err := load(ctx)
		if err != nil {
			return nil, err
		}
		c.groups = groups
		c.loaded = true
	}

	var result []model.Group
	for _, group := range c.groups {
		if group.Name == name {
			result = append(result, group)
		}
	}
	return result, nil
}

// vaultGroupIDs returns the UUIDs of the groups that have access to a vault.
func (c *Client) vaultGroupIDs(ctx context.Context, vaultID string) ([]string, error) {
	accessors := true
	vault, err := c.sdkClient.Vaults().Get(ctx, vaultID, sdk.VaultGetParams{Accessors: &accessors})
	if err != nil {
		return nil, err
	}

	var groupIDs []string
	for _, access := range vault.Access {
		if access.AccessorType == sdk.VaultAccessorTypeGroup {
			groupIDs = append(groupIDs, access.AccessorUuid)
		}
	}
	return groupIDs, nil
}

// collectGroups reads every group with access to one of vaultIDs once. A vault
// whose access can't be read is skipped, since the caller may see a vault
// without being allowed to see who else can.
func collectGroups(
	ctx context.Context,
	vaultIDs []string,
	groupIDsOf func(ctx context.Context, vaultID string) ([]string, error),
	getGroup func(ctx context.Context, groupID string) (*model.Group, error),
) ([]model.Group, error) {
	seen := make(map[string]struct{})
	var result []model.Group
	for _, vaultID := range vaultIDs {
		groupIDs, err := groupIDsOf(ctx, vaultID)
		if err != nil {
			tflog.Warn(ctx, "skipping vault whose access could not be read", map[string]any{"vault_uuid": vaultID, "error": err.Error()})
			continue
		}
		for _, groupID := range groupIDs {
			if _, done := seen[groupID]; done {
				continue
			}
			seen[groupID] = struct{}{}

			group, err := getGroup(ctx, groupID)
			if err != nil {
				return nil, err
			}
			result = append(result, *group)
		}
	}
	return result, nil
}

// CLI returns a client for the 1Password CLI signed in as the provider's
// account. Service accounts can't manage Connect servers or create service
// accounts, so only desktop app authentication has one.
func (c *Client) CLI() (*cli.Client, error) {
	if c.config.Account == "" {
		return nil, errors.New("this requires desktop app authentication: set `account` in the provider configuration. Service accounts and 1Password Connect can't do this")
	}
	runner, err := cli.NewExecRunner(c.config.Account)
	if err != nil {
		return nil, err
	}
	return cli.NewClient(runner), nil
}

func NewClient(ctx context.Context, config SDKConfig) (*Client, error) {
	var sdkClient *sdk.Client
	var err error

	integrationName, integrationVersion, found := strings.Cut(config.ProviderUserAgent, "/")
	if !found {
		return nil, fmt.Errorf("invalid ProviderUserAgent format: expected 'name/version', got %q", config.ProviderUserAgent)
	}

	// Initialize with service account token if provided, otherwise use desktop integration
	if config.ServiceAccountToken != "" {
		sdkClient, err = sdk.NewClient(ctx,
			sdk.WithServiceAccountToken(config.ServiceAccountToken),
			sdk.WithIntegrationInfo(integrationName, integrationVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("SDK client creation with service account failed: %w", err)
		}
	} else {
		// Fall back to desktop integration
		sdkClient, err = sdk.NewClient(ctx,
			sdk.WithDesktopAppIntegration(config.Account),
			sdk.WithIntegrationInfo(integrationName, integrationVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("SDK client creation with desktop integration failed: %w", err)
		}
	}

	return &Client{
		sdkClient: sdkClient,
		config:    config,
	}, nil
}

// resolveVaultUUID resolves a vault name to a UUID
func (c *Client) resolveVaultUUID(ctx context.Context, vaultQuery string) (string, error) {
	if util.IsValidUUID(vaultQuery) {
		return vaultQuery, nil
	}

	// Vault value is a name, resolve it to UUID
	vaults, err := c.GetVaultsByTitle(ctx, vaultQuery)
	if err != nil {
		return "", fmt.Errorf("failed to get vault by title: %w", err)
	}
	if len(vaults) == 0 {
		return "", fmt.Errorf("no vault found with name %q", vaultQuery)
	}
	if len(vaults) > 1 {
		return "", fmt.Errorf("multiple vaults found with name %q", vaultQuery)
	}
	return vaults[0].ID, nil
}
