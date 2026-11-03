package provider

import (
	"context"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

func TestAccVaultResourceRejectsConnect(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccProviderConfig("http://127.0.0.1:1") + `
resource "onepassword_vault" "test" {
  name = "test-vault"
}`,
			ExpectError: regexp.MustCompile(`onepassword_vault resource cannot be used`),
		}},
	})
}

func TestVaultPermissionRoundTrip(t *testing.T) {
	ctx := context.Background()
	permissions, diagnostics := terraformPermissionsFromBitmask(
		ctx,
		model.VaultPermissionReadItems|model.VaultPermissionCreateItems|model.VaultPermissionManageVault,
	)
	if diagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", diagnostics)
	}

	groups, groupDiagnostics := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: vaultGroupPermissionAttrTypes}, []OnePasswordVaultGroupPermissionModel{{
		GroupID:     types.StringValue("group1"),
		Permissions: permissions,
	}})
	if groupDiagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", groupDiagnostics)
	}

	access, diagnostics := vaultAccessFromTerraform(ctx, groups)
	if diagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", diagnostics)
	}
	if len(access) != 1 {
		t.Fatalf("Expected one group, got %d", len(access))
	}
	expected := model.VaultPermissionReadItems | model.VaultPermissionCreateItems | model.VaultPermissionManageVault
	if access[0].GroupID != "group1" || access[0].Permissions != expected {
		t.Fatalf("Unexpected access: %+v", access[0])
	}
}

func TestRefreshManagedVaultAccess(t *testing.T) {
	ctx := context.Background()
	permissions, diagnostics := types.SetValueFrom(ctx, types.StringType, []string{"read_items"})
	if diagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", diagnostics)
	}
	managed, diagnostics := types.SetValueFrom(ctx, types.ObjectType{AttrTypes: vaultGroupPermissionAttrTypes}, []OnePasswordVaultGroupPermissionModel{
		{GroupID: types.StringValue("managed"), Permissions: permissions},
		{GroupID: types.StringValue("removed"), Permissions: permissions},
	})
	if diagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", diagnostics)
	}

	refreshed, diagnostics := refreshManagedVaultAccess(ctx, managed, []model.VaultGroupAccess{
		{GroupID: "managed", Permissions: model.VaultPermissionReadItems | model.VaultPermissionCreateItems},
		{GroupID: "external", Permissions: model.VaultPermissionManageVault},
	})
	if diagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", diagnostics)
	}

	var groups []OnePasswordVaultGroupPermissionModel
	diagnostics = refreshed.ElementsAs(ctx, &groups, false)
	if diagnostics.HasError() {
		t.Fatalf("Unexpected diagnostics: %v", diagnostics)
	}
	if len(groups) != 1 || groups[0].GroupID.ValueString() != "managed" {
		t.Fatalf("Expected only the configured, existing group, got %+v", groups)
	}
}

func TestVaultUUIDFromTerraformID(t *testing.T) {
	tests := map[string]string{
		"vaults/abc":       "abc",
		"abc":              "",
		"vaults/":          "",
		"items/abc":        "",
		"vaults/abc/extra": "",
	}
	for input, expected := range tests {
		if actual := vaultUUIDFromTerraformID(input); actual != expected {
			t.Errorf("vaultUUIDFromTerraformID(%q) = %q, expected %q", input, actual, expected)
		}
	}
}

// fakeVaultManager records the permission calls the resource makes against a
// vault whose actual group access is fixed.
type fakeVaultManager struct {
	actual  []model.VaultGroupAccess
	granted []model.VaultGroupAccess
	updated []model.VaultGroupAccess
	revoked []string
}

func (f *fakeVaultManager) GetVaultDetails(_ context.Context, uuid string) (*model.Vault, error) {
	return &model.Vault{ID: uuid, GroupAccess: f.actual}, nil
}

func (f *fakeVaultManager) CreateVault(_ context.Context, vault *model.Vault, _ bool) (*model.Vault, error) {
	return vault, nil
}

func (f *fakeVaultManager) UpdateVault(_ context.Context, vault *model.Vault) (*model.Vault, error) {
	return vault, nil
}

func (f *fakeVaultManager) DeleteVault(_ context.Context, _ string) error {
	return nil
}

func (f *fakeVaultManager) GrantVaultGroupPermissions(_ context.Context, _ string, access []model.VaultGroupAccess) error {
	f.granted = append(f.granted, access...)
	return nil
}

func (f *fakeVaultManager) UpdateVaultGroupPermissions(_ context.Context, _ string, access []model.VaultGroupAccess) error {
	f.updated = append(f.updated, access...)
	return nil
}

func (f *fakeVaultManager) RevokeVaultGroupPermission(_ context.Context, _, groupID string) error {
	f.revoked = append(f.revoked, groupID)
	return nil
}

func TestReconcileVaultGroupPermissionsUsesActualAccess(t *testing.T) {
	read := model.VaultPermissionReadItems
	write := model.VaultPermissionReadItems | model.VaultPermissionCreateItems
	manager := &fakeVaultManager{actual: []model.VaultGroupAccess{
		{GroupID: "imported", Permissions: read},
		{GroupID: "unchanged", Permissions: write},
		{GroupID: "dropped", Permissions: read},
	}}
	r := &OnePasswordVaultResource{vaultManager: manager}

	previous := []model.VaultGroupAccess{
		{GroupID: "unchanged", Permissions: write},
		{GroupID: "dropped", Permissions: read},
		{GroupID: "gone", Permissions: read},
	}
	desired := []model.VaultGroupAccess{
		{GroupID: "imported", Permissions: write},
		{GroupID: "unchanged", Permissions: write},
		{GroupID: "new", Permissions: read},
	}
	if err := r.reconcileVaultGroupPermissions(context.Background(), "vault", previous, desired); err != nil {
		t.Fatal(err)
	}

	// A group that already has access is updated, not granted again, even
	// when state does not know it.
	if len(manager.granted) != 1 || manager.granted[0].GroupID != "new" {
		t.Errorf("granted = %+v, expected only new", manager.granted)
	}
	if len(manager.updated) != 1 || manager.updated[0].GroupID != "imported" {
		t.Errorf("updated = %+v, expected only imported", manager.updated)
	}
	// A group that has already lost its access is not revoked again.
	if len(manager.revoked) != 1 || manager.revoked[0] != "dropped" {
		t.Errorf("revoked = %+v, expected only dropped", manager.revoked)
	}
}

func TestCreateOnlyBool(t *testing.T) {
	ctx := context.Background()
	schemaType := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"allow_admins_access": tftypes.Bool}}
	object := func(value any) tftypes.Value {
		return tftypes.NewValue(schemaType, map[string]tftypes.Value{"allow_admins_access": tftypes.NewValue(tftypes.Bool, value)})
	}

	tests := map[string]struct {
		state     tftypes.Value
		stateBool types.Bool
		planBool  types.Bool
		wantError bool
	}{
		"create":          {state: tftypes.NewValue(schemaType, nil), stateBool: types.BoolNull(), planBool: types.BoolValue(true)},
		"unchanged":       {state: object(true), stateBool: types.BoolValue(true), planBool: types.BoolValue(true)},
		"after import":    {state: object(nil), stateBool: types.BoolNull(), planBool: types.BoolValue(true)},
		"changed":         {state: object(true), stateBool: types.BoolValue(true), planBool: types.BoolValue(false), wantError: true},
		"unknown in plan": {state: object(true), stateBool: types.BoolValue(true), planBool: types.BoolUnknown()},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := planmodifier.BoolRequest{
				Path:       path.Root("allow_admins_access"),
				State:      tfsdk.State{Raw: test.state},
				Plan:       tfsdk.Plan{Raw: object(true)},
				StateValue: test.stateBool,
				PlanValue:  test.planBool,
			}
			resp := &planmodifier.BoolResponse{PlanValue: test.planBool}
			createOnlyBool{}.PlanModifyBool(ctx, req, resp)
			if resp.Diagnostics.HasError() != test.wantError {
				t.Errorf("error = %v, expected %v: %v", resp.Diagnostics.HasError(), test.wantError, resp.Diagnostics)
			}
			if resp.RequiresReplace {
				t.Error("planned a replacement")
			}
		})
	}
}
