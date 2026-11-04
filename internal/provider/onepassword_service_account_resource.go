package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
)

var _ resource.Resource = &OnePasswordServiceAccountResource{}

const serviceAccountReason = "op can't change a service account after it is created, and replacing it would leave the old one behind, because only the 1Password web interface can delete it. Create a new resource and delete the old service account in the web interface."

// serviceAccountAPI is the part of the 1Password CLI client the service
// account resource uses.
type serviceAccountAPI interface {
	CreateServiceAccount(ctx context.Context, name string, vaults []cli.ServiceAccountVault, canCreateVaults bool, expiresIn string) (string, error)
}

type OnePasswordServiceAccountResource struct {
	serviceAccounts serviceAccountAPI
	items           secretItemStore
}

type OnePasswordServiceAccountResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Vaults          types.Set    `tfsdk:"vaults"`
	CanCreateVaults types.Bool   `tfsdk:"can_create_vaults"`
	ExpiresIn       types.String `tfsdk:"expires_in"`
	TokenVault      types.String `tfsdk:"token_vault"`
	TokenTitle      types.String `tfsdk:"token_title"`
}

type OnePasswordServiceAccountVaultModel struct {
	ID          types.String `tfsdk:"id"`
	Permissions types.Set    `tfsdk:"permissions"`
}

func NewOnePasswordServiceAccountResource() resource.Resource {
	return &OnePasswordServiceAccountResource{}
}

func (r *OnePasswordServiceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *OnePasswordServiceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	createOnly := []planmodifier.String{createOnlyString{reason: serviceAccountReason}}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Creates a 1Password service account and writes its token to a 1Password item. The service account can't be changed, read or deleted by Terraform afterwards: destroying the resource only deletes the token item. Requires desktop app authentication and the 1Password CLI (`op`) on `PATH`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The UUID of the token item. op does not return an ID for the service account itself.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the service account. Can only be set when it is created.",
				Required:            true,
				PlanModifiers:       createOnly,
			},
			"vaults": schema.SetNestedAttribute{
				MarkdownDescription: "The vaults the service account can access. Can only be set when it is created. A service account can't access Personal, Private or Employee vaults.",
				Optional:            true,
				PlanModifiers: []planmodifier.Set{
					createOnlySet{reason: serviceAccountReason},
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "The UUID of the vault.",
							Required:            true,
						},
						"permissions": schema.SetAttribute{
							MarkdownDescription: "The permissions in the vault: `read_items`, `write_items` (requires `read_items`) and `share_items` (requires `read_items`). Without it the service account gets `read_items`.",
							Optional:            true,
							ElementType:         types.StringType,
							Validators: []validator.Set{
								setvalidator.ValueStringsAre(stringvalidator.OneOf("read_items", "write_items", "share_items")),
							},
						},
					},
				},
			},
			"can_create_vaults": schema.BoolAttribute{
				MarkdownDescription: "Whether the service account can create vaults. Defaults to `false`. Can only be set when it is created. A service account needs this or at least one vault.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{
					createOnlyBool{},
				},
			},
			"expires_in": schema.StringAttribute{
				MarkdownDescription: "How long the service account is valid, in op's duration format, such as `90d` or `12w`. Without it the service account does not expire. Can only be set when it is created.",
				Optional:            true,
				PlanModifiers:       createOnly,
			},
			"token_vault": schema.StringAttribute{
				MarkdownDescription: "UUID of the vault to write the token item to. Can only be set when the service account is created.",
				Required:            true,
				PlanModifiers:       createOnly,
			},
			"token_title": schema.StringAttribute{
				MarkdownDescription: "Title of the token item. The item is a secure note with the concealed field `token` and the field `service_account`. Can only be set when the service account is created.",
				Required:            true,
				PlanModifiers:       createOnly,
			},
		},
	}
}

func (r *OnePasswordServiceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	connect, items := configureConnect(req.ProviderData, "onepassword_service_account", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	serviceAccounts, ok := connect.(serviceAccountAPI)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type", fmt.Sprintf("Expected a 1Password CLI client, got: %T. Please report this issue to the provider developers.", connect))
		return
	}
	r.serviceAccounts, r.items = serviceAccounts, items
}

func (r *OnePasswordServiceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan OnePasswordServiceAccountResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()

	var vaultModels []OnePasswordServiceAccountVaultModel
	resp.Diagnostics.Append(plan.Vaults.ElementsAs(ctx, &vaultModels, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(vaultModels) == 0 && !plan.CanCreateVaults.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("vaults"),
			"Service account without access",
			"A service account needs at least one vault or can_create_vaults = true.",
		)
		return
	}
	vaults := make([]cli.ServiceAccountVault, len(vaultModels))
	for i, vault := range vaultModels {
		var permissions []string
		resp.Diagnostics.Append(vault.Permissions.ElementsAs(ctx, &permissions, false)...)
		vaults[i] = cli.ServiceAccountVault{VaultID: vault.ID.ValueString(), Permissions: sortedPermissions(permissions)}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	token, err := r.serviceAccounts.CreateServiceAccount(ctx, name, vaults, plan.CanCreateVaults.ValueBool(), plan.ExpiresIn.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("1Password service account create error", fmt.Sprintf("Could not create service account %q: %s", name, err))
		return
	}

	itemID, err := writeSecretItem(ctx, r.items, plan.TokenVault.ValueString(), plan.TokenTitle.ValueString(), "Service account", []secretField{
		{label: "token", value: token, concealed: true},
		{label: "service_account", value: name},
	})
	if err != nil {
		// op can't delete the service account, and its token is now lost.
		resp.Diagnostics.AddError(
			"1Password service account create error",
			fmt.Sprintf("Service account %q was created, but its token could not be written to an item, so the token is lost: %s. Delete the service account in the 1Password web interface.", name, err),
		)
		return
	}

	plan.ID = types.StringValue(itemID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *OnePasswordServiceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state OnePasswordServiceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// op can't read a service account, so only its token item is checked.
	if _, err := r.items.GetItem(ctx, state.ID.ValueString(), state.TokenVault.ValueString()); err != nil {
		if !isNotFoundError(err) {
			resp.Diagnostics.AddError("1Password service account read error", fmt.Sprintf("Could not read the token item: %s", err))
			return
		}
		resp.Diagnostics.AddWarning(
			"Service account token item is missing",
			fmt.Sprintf("The token item of service account %q no longer exists, and op can't show the token again. Delete the service account in the 1Password web interface and create a new one.", state.Name.ValueString()),
		)
	}
}

func (r *OnePasswordServiceAccountResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Every attribute is create-only, so plans never reach Update.
	resp.Diagnostics.AddError("1Password service account update error", serviceAccountReason)
}

func (r *OnePasswordServiceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state OnePasswordServiceAccountResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := deleteSecretItem(ctx, r.items, state.TokenVault.ValueString(), state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("1Password service account delete error", fmt.Sprintf("Could not delete the token item: %s", err))
		return
	}
	resp.Diagnostics.AddWarning(
		"Service account still exists",
		fmt.Sprintf("Its token item was deleted, but service account %q still exists: op can't delete service accounts. Delete it in the 1Password web interface.", state.Name.ValueString()),
	)
}

// sortedPermissions puts read_items first, since op requires it before the
// permissions that depend on it, and keeps the rest in a stable order.
func sortedPermissions(permissions []string) []string {
	order := map[string]int{"read_items": 0, "write_items": 1, "share_items": 2}
	result := append([]string(nil), permissions...)
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && order[result[j]] < order[result[j-1]]; j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}
	return result
}

// createOnlySet rejects changes to a set that can only be set when the
// resource is created, instead of replacing the resource.
type createOnlySet struct {
	reason string
}

func (m createOnlySet) Description(_ context.Context) string {
	return "The value can only be set when the resource is created."
}

func (m createOnlySet) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m createOnlySet) PlanModifySet(_ context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	if req.PlanValue.IsUnknown() || req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Attribute can only be set at creation", fmt.Sprintf("%s can't be changed: %s", req.Path, m.reason))
}
