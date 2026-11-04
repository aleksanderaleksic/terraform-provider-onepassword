package provider

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

type fakeServiceAccounts struct {
	calls  []string
	vaults []cli.ServiceAccountVault
}

func (f *fakeServiceAccounts) CreateServiceAccount(_ context.Context, name string, vaults []cli.ServiceAccountVault, canCreateVaults bool, expiresIn string) (string, error) {
	f.calls = append(f.calls, name)
	f.vaults = vaults
	return "ops_secret", nil
}

func serviceAccountModel(t *testing.T, vaults map[string][]string, canCreateVaults bool) OnePasswordServiceAccountResourceModel {
	t.Helper()
	ctx := context.Background()
	objectType := types.ObjectType{AttrTypes: map[string]attr.Type{"id": types.StringType, "permissions": types.SetType{ElemType: types.StringType}}}
	var models []OnePasswordServiceAccountVaultModel
	for id, permissions := range vaults {
		models = append(models, OnePasswordServiceAccountVaultModel{ID: types.StringValue(id), Permissions: stringSet(t, permissions...)})
	}
	set := types.SetNull(objectType)
	if vaults != nil {
		var diagnostics diag.Diagnostics
		set, diagnostics = types.SetValueFrom(ctx, objectType, models)
		if diagnostics.HasError() {
			t.Fatal(diagnostics)
		}
	}
	return OnePasswordServiceAccountResourceModel{
		ID:              types.StringUnknown(),
		Name:            types.StringValue("ci"),
		Vaults:          set,
		CanCreateVaults: types.BoolValue(canCreateVaults),
		ExpiresIn:       types.StringNull(),
		TokenVault:      types.StringValue("INFRA"),
		TokenTitle:      types.StringValue("ci service account"),
	}
}

func TestServiceAccountCreateWritesTokenItem(t *testing.T) {
	ctx := context.Background()
	serviceAccounts, items := &fakeServiceAccounts{}, &fakeItems{}
	r := &OnePasswordServiceAccountResource{serviceAccounts: serviceAccounts, items: items}

	plan := resourceValue(t, r, serviceAccountModel(t, map[string][]string{"V1": {"write_items", "read_items"}}, false))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(ctx, fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}

	if got := items.field(t, "ITEM1", "token"); got != "ops_secret" {
		t.Errorf("token field = %q", got)
	}
	var state OnePasswordServiceAccountResourceModel
	resp.State.Get(ctx, &state)
	if state.ID.ValueString() != "ITEM1" {
		t.Errorf("id = %q, expected the token item", state.ID.ValueString())
	}
	// op wants read_items before the permissions that depend on it.
	if !reflect.DeepEqual(serviceAccounts.vaults, []cli.ServiceAccountVault{{VaultID: "V1", Permissions: []string{"read_items", "write_items"}}}) {
		t.Errorf("vaults = %+v", serviceAccounts.vaults)
	}
}

func TestServiceAccountCreateNeedsAccess(t *testing.T) {
	serviceAccounts := &fakeServiceAccounts{}
	r := &OnePasswordServiceAccountResource{serviceAccounts: serviceAccounts, items: &fakeItems{}}

	plan := resourceValue(t, r, serviceAccountModel(t, nil, false))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if !resp.Diagnostics.HasError() || len(serviceAccounts.calls) != 0 {
		t.Errorf("expected a refusal without creating anything: %v %q", resp.Diagnostics, serviceAccounts.calls)
	}

	plan = resourceValue(t, r, serviceAccountModel(t, nil, true))
	resp = &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("can_create_vaults alone was refused: %v", resp.Diagnostics)
	}
}

func TestServiceAccountCreateExplainsLostToken(t *testing.T) {
	r := &OnePasswordServiceAccountResource{serviceAccounts: &fakeServiceAccounts{}, items: &fakeItems{createErr: errors.New("no access to vault")}}
	plan := resourceValue(t, r, serviceAccountModel(t, nil, true))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)

	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "web interface") {
		t.Errorf("expected an error pointing to the web interface, got %v", resp.Diagnostics)
	}
	if strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "ops_secret") {
		t.Error("the error contains the token")
	}
}

func createdServiceAccountModel(t *testing.T) OnePasswordServiceAccountResourceModel {
	data := serviceAccountModel(t, nil, true)
	data.ID = types.StringValue("ITEM1")
	return data
}

func TestServiceAccountReadWarnsWhenTokenItemIsGone(t *testing.T) {
	r := &OnePasswordServiceAccountResource{serviceAccounts: &fakeServiceAccounts{}, items: &fakeItems{}}
	state := resourceValue(t, r, createdServiceAccountModel(t))
	resp := &fwresource.ReadResponse{State: state}
	r.Read(context.Background(), fwresource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || len(resp.Diagnostics.Warnings()) != 1 || resp.State.Raw.IsNull() {
		t.Errorf("expected the service account kept with one warning: %v", resp.Diagnostics)
	}
}

func TestServiceAccountDeleteRemovesTokenItemAndWarns(t *testing.T) {
	items := &fakeItems{items: map[string]*model.Item{"ITEM1": {ID: "ITEM1"}}}
	r := &OnePasswordServiceAccountResource{serviceAccounts: &fakeServiceAccounts{}, items: items}
	state := resourceValue(t, r, createdServiceAccountModel(t))
	resp := &fwresource.DeleteResponse{State: state}
	r.Delete(context.Background(), fwresource.DeleteRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || len(items.items) != 0 {
		t.Fatalf("token item not deleted: %v", resp.Diagnostics)
	}
	if warnings := resp.Diagnostics.Warnings(); len(warnings) != 1 || !strings.Contains(warnings[0].Detail(), "web interface") {
		t.Errorf("expected a warning that the service account still exists, got %v", resp.Diagnostics)
	}
}

func TestCreateOnlySet(t *testing.T) {
	ctx := context.Background()
	objectType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"vaults": tftypes.Set{ElementType: tftypes.String}}}
	existing := tftypes.NewValue(objectType, map[string]tftypes.Value{"vaults": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, nil)})

	tests := map[string]struct {
		state     tftypes.Value
		stateSet  types.Set
		planSet   types.Set
		wantError bool
	}{
		"create":    {state: tftypes.NewValue(objectType, nil), stateSet: types.SetNull(types.StringType), planSet: stringSet(t, "V1")},
		"unchanged": {state: existing, stateSet: stringSet(t, "V1"), planSet: stringSet(t, "V1")},
		"changed":   {state: existing, stateSet: stringSet(t, "V1"), planSet: stringSet(t, "V2"), wantError: true},
		"unknown":   {state: existing, stateSet: stringSet(t, "V1"), planSet: types.SetUnknown(types.StringType)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := planmodifier.SetRequest{
				Path:       path.Root("vaults"),
				State:      tfsdk.State{Raw: test.state},
				Plan:       tfsdk.Plan{Raw: existing},
				StateValue: test.stateSet,
				PlanValue:  test.planSet,
			}
			resp := &planmodifier.SetResponse{PlanValue: test.planSet}
			createOnlySet{reason: "test"}.PlanModifySet(ctx, req, resp)
			if resp.Diagnostics.HasError() != test.wantError || resp.RequiresReplace {
				t.Errorf("error = %v, replace = %v", resp.Diagnostics, resp.RequiresReplace)
			}
		})
	}
}

func TestSortedPermissions(t *testing.T) {
	got := sortedPermissions([]string{"share_items", "write_items", "read_items"})
	if !reflect.DeepEqual(got, []string{"read_items", "write_items", "share_items"}) {
		t.Errorf("sortedPermissions = %q", got)
	}
}

func TestAccServiceAccountRejectsConnect(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccProviderConfig("http://127.0.0.1:1") + `
resource "onepassword_service_account" "test" {
  name              = "ci"
  can_create_vaults = true
  token_vault       = "INFRA"
  token_title       = "ci service account"
}`,
			ExpectError: regexp.MustCompile(`cannot be used with 1Password Connect\s+authentication`),
		}},
	})
}
