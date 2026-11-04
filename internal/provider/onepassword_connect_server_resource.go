package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
)

var _ resource.Resource = &OnePasswordConnectServerResource{}

const credentialsItemReason = "op only returns a Connect server's credentials when the server is created, so they can't be written to another item later. Move the item in 1Password and update the configuration to match, or replace the server."

type OnePasswordConnectServerResource struct {
	connect connectAPI
	items   secretItemStore
}

type OnePasswordConnectServerResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Vaults            types.Set    `tfsdk:"vaults"`
	CredentialsVault  types.String `tfsdk:"credentials_vault"`
	CredentialsTitle  types.String `tfsdk:"credentials_title"`
	CredentialsItemID types.String `tfsdk:"credentials_item_id"`
}

func NewOnePasswordConnectServerResource() resource.Resource {
	return &OnePasswordConnectServerResource{}
}

func (r *OnePasswordConnectServerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connect_server"
}

func (r *OnePasswordConnectServerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a 1Password Connect server and writes its credentials file to a 1Password item. Requires desktop app authentication and the 1Password CLI (`op`) on `PATH`: service accounts and 1Password Connect can't manage Connect servers.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The UUID of the Connect server.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the Connect server. It must be unique in the account.",
				Required:            true,
			},
			"vaults": schema.SetAttribute{
				MarkdownDescription: "UUIDs of the vaults the Connect server can access. op can't list a server's vaults, so access changed outside Terraform is not detected.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"credentials_vault": schema.StringAttribute{
				MarkdownDescription: "UUID of the vault to write the credentials item to. Can only be set when the server is created.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					createOnlyString{reason: credentialsItemReason},
				},
			},
			"credentials_title": schema.StringAttribute{
				MarkdownDescription: "Title of the credentials item. The item is a secure note with the concealed field `credentials` (the contents of `1password-credentials.json`) and the fields `server_id` and `server_name`. Can only be set when the server is created.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					createOnlyString{reason: credentialsItemReason},
				},
			},
			"credentials_item_id": schema.StringAttribute{
				MarkdownDescription: "The UUID of the credentials item.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *OnePasswordConnectServerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.connect, r.items = configureConnect(req.ProviderData, "onepassword_connect_server", &resp.Diagnostics)
}

func (r *OnePasswordConnectServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan OnePasswordConnectServerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()

	// op finds servers by name too, and a second server with the same name
	// would make those lookups ambiguous.
	servers, err := r.connect.ListConnectServers(ctx)
	if err != nil {
		resp.Diagnostics.AddError("1Password Connect server create error", fmt.Sprintf("Could not list Connect servers: %s", err))
		return
	}
	for _, server := range servers {
		if server.Name == name {
			resp.Diagnostics.AddError(
				"1Password Connect server already exists",
				fmt.Sprintf("A Connect server named %q already exists (%s). Its credentials can't be read again, so it can't be imported: delete or rename it, or choose another name.", name, server.ID),
			)
			return
		}
	}

	var vaultIDs []string
	resp.Diagnostics.Append(plan.Vaults.ElementsAs(ctx, &vaultIDs, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	server, credentials, err := r.connect.CreateConnectServer(ctx, name, vaultIDs)
	if err != nil {
		resp.Diagnostics.AddError("1Password Connect server create error", fmt.Sprintf("Could not create Connect server %q: %s", name, err))
		return
	}

	itemID, err := writeSecretItem(ctx, r.items, plan.CredentialsVault.ValueString(), plan.CredentialsTitle.ValueString(), "Connect server", []secretField{
		{label: "credentials", value: string(credentials), concealed: true},
		{label: "server_id", value: server.ID},
		{label: "server_name", value: server.Name},
	})
	if err != nil {
		// Without the item the credentials are lost, so the server is useless.
		if cleanupErr := r.connect.DeleteConnectServer(ctx, server.ID); cleanupErr != nil {
			resp.Diagnostics.AddError("1Password Connect server create error", fmt.Sprintf("Could not write the credentials item: %s. Deleting Connect server %s also failed, delete it manually: %s", err, server.ID, cleanupErr))
			return
		}
		resp.Diagnostics.AddError("1Password Connect server create error", fmt.Sprintf("Could not write the credentials item, so the new Connect server was deleted again: %s", err))
		return
	}

	plan.ID = types.StringValue(server.ID)
	plan.Name = types.StringValue(server.Name)
	plan.CredentialsItemID = types.StringValue(itemID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *OnePasswordConnectServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state OnePasswordConnectServerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	server, err := r.connect.GetConnectServer(ctx, state.ID.ValueString())
	if errors.Is(err, cli.ErrNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("1Password Connect server read error", fmt.Sprintf("Could not get Connect server %q: %s", state.ID.ValueString(), err))
		return
	}
	state.Name = types.StringValue(server.Name)

	if _, err := r.items.GetItem(ctx, state.CredentialsItemID.ValueString(), state.CredentialsVault.ValueString()); err != nil {
		if !isNotFoundError(err) {
			resp.Diagnostics.AddError("1Password Connect server read error", fmt.Sprintf("Could not read the credentials item: %s", err))
			return
		}
		resp.Diagnostics.AddWarning(
			"Connect server credentials item is missing",
			fmt.Sprintf("The credentials item of Connect server %q no longer exists, and op can't return the credentials again. Replace the server to get new credentials: tofu apply -replace=<address>.", server.Name),
		)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *OnePasswordConnectServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state OnePasswordConnectServerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()

	if !plan.Name.Equal(state.Name) {
		if err := r.connect.RenameConnectServer(ctx, id, plan.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("1Password Connect server update error", fmt.Sprintf("Could not rename Connect server %q: %s", id, err))
			return
		}
	}

	var previous, desired []string
	resp.Diagnostics.Append(state.Vaults.ElementsAs(ctx, &previous, false)...)
	resp.Diagnostics.Append(plan.Vaults.ElementsAs(ctx, &desired, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	grants, revokes := setDifference(desired, previous), setDifference(previous, desired)
	for _, vaultID := range grants {
		if err := r.connect.GrantConnectServerVault(ctx, id, vaultID); err != nil {
			resp.Diagnostics.AddError("1Password Connect server update error", fmt.Sprintf("Could not grant Connect server %q access to vault %q: %s", id, vaultID, err))
			return
		}
	}
	for _, vaultID := range revokes {
		if err := r.connect.RevokeConnectServerVault(ctx, id, vaultID); err != nil {
			resp.Diagnostics.AddError("1Password Connect server update error", fmt.Sprintf("Could not revoke Connect server %q access to vault %q: %s", id, vaultID, err))
			return
		}
	}

	plan.ID = state.ID
	plan.CredentialsItemID = state.CredentialsItemID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *OnePasswordConnectServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state OnePasswordConnectServerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.connect.DeleteConnectServer(ctx, state.ID.ValueString()); err != nil && !errors.Is(err, cli.ErrNotFound) {
		resp.Diagnostics.AddError("1Password Connect server delete error", fmt.Sprintf("Could not delete Connect server %q: %s", state.ID.ValueString(), err))
		return
	}
	if err := deleteSecretItem(ctx, r.items, state.CredentialsVault.ValueString(), state.CredentialsItemID.ValueString()); err != nil {
		resp.Diagnostics.AddError("1Password Connect server delete error", fmt.Sprintf("The Connect server was deleted, but its credentials item could not be: %s", err))
	}
}

// setDifference returns the values in a that are not in b.
func setDifference(a, b []string) []string {
	inB := make(map[string]struct{}, len(b))
	for _, value := range b {
		inB[value] = struct{}{}
	}
	var result []string
	for _, value := range a {
		if _, exists := inB[value]; !exists {
			result = append(result, value)
		}
	}
	return result
}
