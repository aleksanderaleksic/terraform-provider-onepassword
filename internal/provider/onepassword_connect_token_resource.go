package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
)

var _ resource.Resource = &OnePasswordConnectTokenResource{}

// connectTokenAccess maps the access values in the schema to op's suffixes.
var connectTokenAccess = map[string]string{
	"read":  "r",
	"write": "w",
}

type OnePasswordConnectTokenResource struct {
	connect connectAPI
	items   secretItemStore
}

type OnePasswordConnectTokenResourceModel struct {
	ID          types.String `tfsdk:"id"`
	ServerID    types.String `tfsdk:"server_id"`
	Name        types.String `tfsdk:"name"`
	Vaults      types.Set    `tfsdk:"vaults"`
	ExpiresIn   types.String `tfsdk:"expires_in"`
	TokenVault  types.String `tfsdk:"token_vault"`
	TokenTitle  types.String `tfsdk:"token_title"`
	TokenItemID types.String `tfsdk:"token_item_id"`
}

type OnePasswordConnectTokenVaultModel struct {
	ID     types.String `tfsdk:"id"`
	Access types.String `tfsdk:"access"`
}

func NewOnePasswordConnectTokenResource() resource.Resource {
	return &OnePasswordConnectTokenResource{}
}

func (r *OnePasswordConnectTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connect_token"
}

func (r *OnePasswordConnectTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Issues a token for a 1Password Connect server and writes it to a 1Password item. Changing anything but `name` issues a new token and revokes the old one. Requires desktop app authentication and the 1Password CLI (`op`) on `PATH`: service accounts and 1Password Connect can't manage Connect tokens.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The ID of the token.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"server_id": schema.StringAttribute{
				MarkdownDescription: "The UUID of the Connect server to issue the token for.",
				Required:            true,
				PlanModifiers:       replace,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the token. It must be unique among the server's active tokens.",
				Required:            true,
			},
			"vaults": schema.SetNestedAttribute{
				MarkdownDescription: "The vaults the token can access. The Connect server must have access to each of them.",
				Required:            true,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The UUID of the vault.",
							Required:            true,
						},
						"access": schema.StringAttribute{
							MarkdownDescription: "Limits the token to `read` or `write` access to the vault. Without it the token has the server's access.",
							Optional:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("read", "write"),
							},
						},
					},
				},
			},
			"expires_in": schema.StringAttribute{
				MarkdownDescription: "How long the token is valid, in op's duration format, such as `90d` or `12w`. Without it the token does not expire.",
				Optional:            true,
				PlanModifiers:       replace,
			},
			"token_vault": schema.StringAttribute{
				MarkdownDescription: "UUID of the vault to write the token item to.",
				Required:            true,
				PlanModifiers:       replace,
			},
			"token_title": schema.StringAttribute{
				MarkdownDescription: "Title of the token item. The item is a secure note with the concealed field `token` and the fields `server_id` and `token_id`.",
				Required:            true,
				PlanModifiers:       replace,
			},
			"token_item_id": schema.StringAttribute{
				MarkdownDescription: "The UUID of the token item.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *OnePasswordConnectTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.connect, r.items = configureConnect(req.ProviderData, "onepassword_connect_token", &resp.Diagnostics)
}

func (r *OnePasswordConnectTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan OnePasswordConnectTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	serverID, name := plan.ServerID.ValueString(), plan.Name.ValueString()

	// op only prints the token, so the new token's ID is found by its name.
	tokens, err := r.connect.ListConnectTokens(ctx, serverID)
	if err != nil {
		resp.Diagnostics.AddError("1Password Connect token create error", fmt.Sprintf("Could not list the tokens of Connect server %q: %s", serverID, err))
		return
	}
	for _, token := range cli.ActiveConnectTokens(tokens) {
		if token.Name == name {
			resp.Diagnostics.AddError(
				"1Password Connect token already exists",
				fmt.Sprintf("Connect server %q already has an active token named %q (%s). Choose another name or revoke that token.", serverID, name, token.ID),
			)
			return
		}
	}

	var vaultModels []OnePasswordConnectTokenVaultModel
	resp.Diagnostics.Append(plan.Vaults.ElementsAs(ctx, &vaultModels, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaults := make([]cli.ConnectTokenVault, len(vaultModels))
	for i, vault := range vaultModels {
		vaults[i] = cli.ConnectTokenVault{VaultID: vault.ID.ValueString(), Permission: connectTokenAccess[vault.Access.ValueString()]}
	}

	token, value, err := r.connect.CreateConnectToken(ctx, serverID, name, vaults, plan.ExpiresIn.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("1Password Connect token create error", fmt.Sprintf("Could not issue token %q: %s", name, err))
		return
	}

	itemID, err := writeSecretItem(ctx, r.items, plan.TokenVault.ValueString(), plan.TokenTitle.ValueString(), "Connect token", []secretField{
		{label: "token", value: value, concealed: true},
		{label: "server_id", value: serverID},
		{label: "token_id", value: token.ID},
	})
	if err != nil {
		if cleanupErr := r.connect.DeleteConnectToken(ctx, serverID, token.ID); cleanupErr != nil {
			resp.Diagnostics.AddError("1Password Connect token create error", fmt.Sprintf("Could not write the token item: %s. Revoking token %s also failed, revoke it manually: %s", err, token.ID, cleanupErr))
			return
		}
		resp.Diagnostics.AddError("1Password Connect token create error", fmt.Sprintf("Could not write the token item, so the new token was revoked again: %s", err))
		return
	}

	plan.ID = types.StringValue(token.ID)
	plan.TokenItemID = types.StringValue(itemID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *OnePasswordConnectTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state OnePasswordConnectTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tokens, err := r.connect.ListConnectTokens(ctx, state.ServerID.ValueString())
	if errors.Is(err, cli.ErrNotFound) {
		// The server is gone, and its tokens with it.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("1Password Connect token read error", fmt.Sprintf("Could not list the tokens of Connect server %q: %s", state.ServerID.ValueString(), err))
		return
	}

	var found *cli.ConnectToken
	for _, token := range cli.ActiveConnectTokens(tokens) {
		if token.ID == state.ID.ValueString() {
			found = &token
			break
		}
	}
	if found == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.Name = types.StringValue(found.Name)

	if _, err := r.items.GetItem(ctx, state.TokenItemID.ValueString(), state.TokenVault.ValueString()); err != nil {
		if !isNotFoundError(err) {
			resp.Diagnostics.AddError("1Password Connect token read error", fmt.Sprintf("Could not read the token item: %s", err))
			return
		}
		resp.Diagnostics.AddWarning(
			"Connect token item is missing",
			fmt.Sprintf("The item holding token %q no longer exists, and op can't show the token again. Replace the token to issue a new one: tofu apply -replace=<address>.", found.Name),
		)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *OnePasswordConnectTokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state OnePasswordConnectTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Every other attribute replaces the token.
	if !plan.Name.Equal(state.Name) {
		if err := r.connect.RenameConnectToken(ctx, state.ServerID.ValueString(), state.ID.ValueString(), plan.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("1Password Connect token update error", fmt.Sprintf("Could not rename token %q: %s", state.ID.ValueString(), err))
			return
		}
	}

	plan.ID = state.ID
	plan.TokenItemID = state.TokenItemID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *OnePasswordConnectTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state OnePasswordConnectTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.connect.DeleteConnectToken(ctx, state.ServerID.ValueString(), state.ID.ValueString()); err != nil && !errors.Is(err, cli.ErrNotFound) {
		resp.Diagnostics.AddError("1Password Connect token delete error", fmt.Sprintf("Could not revoke token %q: %s", state.ID.ValueString(), err))
		return
	}
	if err := deleteSecretItem(ctx, r.items, state.TokenVault.ValueString(), state.TokenItemID.ValueString()); err != nil {
		resp.Diagnostics.AddError("1Password Connect token delete error", fmt.Sprintf("The token was revoked, but its item could not be deleted: %s", err))
	}
}
