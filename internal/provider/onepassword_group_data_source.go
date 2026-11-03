package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &OnePasswordGroupDataSource{}

func NewOnePasswordGroupDataSource() datasource.DataSource {
	return &OnePasswordGroupDataSource{}
}

// OnePasswordGroupDataSource defines the data source implementation.
type OnePasswordGroupDataSource struct {
	client onepassword.Client
}

// OnePasswordGroupDataSourceModel describes the data source data model.
type OnePasswordGroupDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	UUID        types.String `tfsdk:"uuid"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
	State       types.String `tfsdk:"state"`
}

func (d *OnePasswordGroupDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *OnePasswordGroupDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Use this data source to get details of a group by either its name or uuid. Only available with service account or desktop app authentication. A lookup by name only finds groups with access to a vault the provider can see.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The Terraform resource identifier for this group in the format `groups/<group_id>`.",
				Computed:            true,
			},
			"uuid": schema.StringAttribute{
				MarkdownDescription: "The UUID of the group to retrieve. This field will be populated with the UUID of the group if the group is looked up by its name.",
				Optional:            true,
				Computed:            true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.Expressions{
						path.MatchRoot("name"),
						path.MatchRoot("uuid"),
					}...),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the group to retrieve. This field will be populated with the name of the group if the group is looked up by its UUID.",
				Optional:            true,
				Computed:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "The description of the group.",
				Computed:            true,
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "The type of the group, such as `owners`, `administrators`, `teamMembers` or `userDefined`.",
				Computed:            true,
			},
			"state": schema.StringAttribute{
				MarkdownDescription: "The state of the group, such as `active` or `deleted`.",
				Computed:            true,
			},
		},
	}
}

func (d *OnePasswordGroupDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(onepassword.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected onepassword.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

func (d *OnePasswordGroupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data OnePasswordGroupDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var group *model.Group
	if data.UUID.ValueString() != "" {
		groupByUUID, err := d.client.GetGroup(ctx, data.UUID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read group, got error: %s", err))
			return
		}
		group = groupByUUID
	} else {
		groupsByName, err := d.client.GetGroupsByName(ctx, data.Name.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read group, got error: %s", err))
			return
		}
		if len(groupsByName) == 0 {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("No group found with name '%s'. Only groups with access to a vault the provider can see are found by name; look up a group without vault access by its UUID.", data.Name.ValueString()))
			return
		} else if len(groupsByName) > 1 {
			resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Multiple groups found with name '%s'", data.Name.ValueString()))
			return
		}
		group = &groupsByName[0]
	}

	data = OnePasswordGroupDataSourceModel{
		ID:          types.StringValue(fmt.Sprintf("groups/%s", group.ID)),
		UUID:        types.StringValue(group.ID),
		Name:        types.StringValue(group.Name),
		Description: types.StringValue(group.Description),
		Type:        types.StringValue(group.Type),
		State:       types.StringValue(group.State),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
