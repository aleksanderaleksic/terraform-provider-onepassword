package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

// connectAPI is the part of the 1Password CLI client the Connect resources use.
type connectAPI interface {
	CreateConnectServer(ctx context.Context, name string, vaultIDs []string) (*cli.ConnectServer, []byte, error)
	GetConnectServer(ctx context.Context, server string) (*cli.ConnectServer, error)
	ListConnectServers(ctx context.Context) ([]cli.ConnectServer, error)
	RenameConnectServer(ctx context.Context, id, name string) error
	GrantConnectServerVault(ctx context.Context, id, vaultID string) error
	RevokeConnectServerVault(ctx context.Context, id, vaultID string) error
	DeleteConnectServer(ctx context.Context, id string) error
	CreateConnectToken(ctx context.Context, serverID, name string, vaults []cli.ConnectTokenVault, expiresIn string) (*cli.ConnectToken, string, error)
	ListConnectTokens(ctx context.Context, serverID string) ([]cli.ConnectToken, error)
	RenameConnectToken(ctx context.Context, serverID, id, name string) error
	DeleteConnectToken(ctx context.Context, serverID, id string) error
}

// secretItemStore keeps the secrets the Connect resources create, so they
// never reach state.
type secretItemStore interface {
	CreateItem(ctx context.Context, item *model.Item, vaultUuid string) (*model.Item, error)
	GetItem(ctx context.Context, itemUuid, vaultUuid string) (*model.Item, error)
	DeleteItem(ctx context.Context, item *model.Item, vaultUuid string) error
}

// configureConnect returns the CLI client and the item store for a Connect
// resource, or reports why the provider's authentication can't manage Connect.
func configureConnect(providerData any, typeName string, diagnostics *diag.Diagnostics) (connectAPI, secretItemStore) {
	client, ok := providerData.(onepassword.Client)
	if !ok {
		diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected onepassword.Client, got: %T. Please report this issue to the provider developers.", providerData),
		)
		return nil, nil
	}
	cliProvider, ok := client.(onepassword.CLIProvider)
	if !ok {
		diagnostics.AddError(
			fmt.Sprintf("Unsupported authentication for %s", typeName),
			fmt.Sprintf("%s cannot be used with 1Password Connect authentication. It requires desktop app authentication: set `account` in the provider configuration.", typeName),
		)
		return nil, nil
	}
	connect, err := cliProvider.CLI()
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Unsupported authentication for %s", typeName), err.Error())
		return nil, nil
	}
	return connect, client
}

type secretField struct {
	label     string
	value     string
	concealed bool
}

// writeSecretItem creates a secure note with fields in one section and
// returns its ID.
func writeSecretItem(ctx context.Context, store secretItemStore, vaultID, title, section string, fields []secretField) (string, error) {
	const sectionID = "secret"
	item := &model.Item{
		Title:    title,
		VaultID:  vaultID,
		Category: model.SecureNote,
		Sections: []model.ItemSection{{ID: sectionID, Label: section}},
	}
	for _, field := range fields {
		fieldType := model.FieldTypeString
		if field.concealed {
			fieldType = model.FieldTypeConcealed
		}
		item.Fields = append(item.Fields, model.ItemField{
			ID:           field.label,
			Label:        field.label,
			Type:         fieldType,
			Value:        field.value,
			SectionID:    sectionID,
			SectionLabel: section,
		})
	}

	created, err := store.CreateItem(ctx, item, vaultID)
	if err != nil {
		return "", err
	}
	return created.ID, nil
}

// deleteSecretItem deletes an item written by writeSecretItem. An item that no
// longer exists is not an error.
func deleteSecretItem(ctx context.Context, store secretItemStore, vaultID, itemID string) error {
	if itemID == "" {
		return nil
	}
	err := store.DeleteItem(ctx, &model.Item{ID: itemID, VaultID: vaultID}, vaultID)
	if err != nil && !isNotFoundError(err) {
		return err
	}
	return nil
}

// createOnlyString rejects changes to an attribute that can only be set when
// the resource is created, instead of replacing the resource.
type createOnlyString struct {
	reason string
}

func (m createOnlyString) Description(_ context.Context) string {
	return "The value can only be set when the resource is created."
}

func (m createOnlyString) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m createOnlyString) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	if req.StateValue.IsNull() || req.PlanValue.IsUnknown() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Attribute can only be set at creation", fmt.Sprintf("%s can't be changed: %s", req.Path, m.reason))
}
