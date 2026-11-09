package provider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/cli"
	"github.com/1Password/terraform-provider-onepassword/v3/internal/onepassword/model"
)

// fakeConnect is a Connect server with its tokens, as op would report them.
type fakeConnect struct {
	servers    []cli.ConnectServer
	tokens     []cli.ConnectToken
	getErr     error
	created    []string
	calls      []string
	tokenValue string
}

func (f *fakeConnect) record(format string, args ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

func (f *fakeConnect) CreateConnectServer(_ context.Context, name string, vaultIDs []string) (*cli.ConnectServer, []byte, error) {
	f.record("create server %s %v", name, vaultIDs)
	server := cli.ConnectServer{ID: "SERVER1", Name: name, State: "ACTIVE"}
	f.servers = append(f.servers, server)
	return &server, []byte(`{"verifier":"secret"}`), nil
}

func (f *fakeConnect) GetConnectServer(_ context.Context, id string) (*cli.ConnectServer, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	for _, server := range f.servers {
		if server.ID == id {
			return &server, nil
		}
	}
	return nil, fmt.Errorf("op connect server get: There are 0 servers that match: %w", cli.ErrNotFound)
}

func (f *fakeConnect) ListConnectServers(_ context.Context) ([]cli.ConnectServer, error) {
	return f.servers, nil
}

func (f *fakeConnect) RenameConnectServer(_ context.Context, id, name string) error {
	f.record("rename server %s %s", id, name)
	return nil
}

func (f *fakeConnect) GrantConnectServerVault(_ context.Context, id, vaultID string) error {
	f.record("grant %s %s", id, vaultID)
	return nil
}

func (f *fakeConnect) RevokeConnectServerVault(_ context.Context, id, vaultID string) error {
	f.record("revoke %s %s", id, vaultID)
	return nil
}

func (f *fakeConnect) DeleteConnectServer(_ context.Context, id string) error {
	f.record("delete server %s", id)
	return nil
}

func (f *fakeConnect) CreateConnectToken(_ context.Context, serverID, name string, vaults []cli.ConnectTokenVault, expiresIn string) (*cli.ConnectToken, string, error) {
	f.record("create token %s %s %v %s", serverID, name, vaults, expiresIn)
	token := cli.ConnectToken{ID: "TOKEN1", Name: name, State: "ACTIVE"}
	f.tokens = append(f.tokens, token)
	return &token, f.tokenValue, nil
}

func (f *fakeConnect) ListConnectTokens(_ context.Context, _ string) ([]cli.ConnectToken, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.tokens, nil
}

func (f *fakeConnect) RenameConnectToken(_ context.Context, serverID, id, name string) error {
	f.record("rename token %s %s %s", serverID, id, name)
	return nil
}

func (f *fakeConnect) DeleteConnectToken(_ context.Context, serverID, id string) error {
	f.record("delete token %s %s", serverID, id)
	return nil
}

// fakeItems stores items in memory.
type fakeItems struct {
	items     map[string]*model.Item
	createErr error
}

func (f *fakeItems) CreateItem(_ context.Context, item *model.Item, vaultUuid string) (*model.Item, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if item.VaultID != vaultUuid {
		return nil, errors.New("vault mismatch")
	}
	created := *item
	created.ID = "ITEM1"
	if f.items == nil {
		f.items = map[string]*model.Item{}
	}
	f.items[created.ID] = &created
	return &created, nil
}

func (f *fakeItems) GetItem(_ context.Context, itemUuid, _ string) (*model.Item, error) {
	if item, ok := f.items[itemUuid]; ok {
		return item, nil
	}
	return nil, errors.New("failed to get item using sdk: item couldn't be found")
}

func (f *fakeItems) DeleteItem(_ context.Context, item *model.Item, _ string) error {
	if _, ok := f.items[item.ID]; !ok {
		return errors.New("failed to delete item using sdk: item couldn't be found")
	}
	delete(f.items, item.ID)
	return nil
}

func (f *fakeItems) field(t *testing.T, itemID, label string) string {
	t.Helper()
	item, ok := f.items[itemID]
	if !ok {
		t.Fatalf("item %s was not written", itemID)
	}
	for _, field := range item.Fields {
		if field.Label == label {
			return field.Value
		}
	}
	t.Fatalf("item %s has no field %q", itemID, label)
	return ""
}

// resourceValue turns a resource model into a raw value of the resource's schema.
func resourceValue(t *testing.T, r fwresource.Resource, data any) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	schemaResp := &fwresource.SchemaResponse{}
	r.Schema(ctx, fwresource.SchemaRequest{}, schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema, Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}
	if diagnostics := state.Set(ctx, data); diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return state
}

func emptyState(state tfsdk.State) tfsdk.State {
	return tfsdk.State{Schema: state.Schema, Raw: tftypes.NewValue(state.Raw.Type(), nil)}
}

func stringSet(t *testing.T, values ...string) types.Set {
	t.Helper()
	set, diagnostics := types.SetValueFrom(context.Background(), types.StringType, values)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return set
}

func serverModel(t *testing.T, name string, vaults ...string) OnePasswordConnectServerResourceModel {
	return OnePasswordConnectServerResourceModel{
		ID:                types.StringUnknown(),
		Name:              types.StringValue(name),
		Vaults:            stringSet(t, vaults...),
		CredentialsVault:  types.StringValue("INFRA"),
		CredentialsTitle:  types.StringValue("connect-ailab"),
		CredentialsItemID: types.StringUnknown(),
	}
}

func TestConnectServerCreateWritesCredentialsItem(t *testing.T) {
	ctx := context.Background()
	connect, items := &fakeConnect{}, &fakeItems{}
	r := &OnePasswordConnectServerResource{connect: connect, items: items}

	plan := resourceValue(t, r, serverModel(t, "ailab", "V1"))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(ctx, fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}

	var state OnePasswordConnectServerResourceModel
	resp.State.Get(ctx, &state)
	if state.ID.ValueString() != "SERVER1" || state.CredentialsItemID.ValueString() != "ITEM1" {
		t.Errorf("state = %+v", state)
	}
	if got := items.field(t, "ITEM1", "credentials"); got != `{"verifier":"secret"}` {
		t.Errorf("credentials field = %q", got)
	}
	if got := items.field(t, "ITEM1", "server_id"); got != "SERVER1" {
		t.Errorf("server_id field = %q", got)
	}
	if items.items["ITEM1"].VaultID != "INFRA" {
		t.Errorf("item written to vault %q", items.items["ITEM1"].VaultID)
	}
}

func TestConnectServerCreateRefusesExistingName(t *testing.T) {
	connect := &fakeConnect{servers: []cli.ConnectServer{{ID: "OLD", Name: "ailab"}}}
	r := &OnePasswordConnectServerResource{connect: connect, items: &fakeItems{}}

	plan := resourceValue(t, r, serverModel(t, "ailab"))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)

	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "OLD") {
		t.Fatalf("expected an error naming the existing server, got %v", resp.Diagnostics)
	}
	if len(connect.calls) != 0 {
		t.Errorf("unexpected calls %q", connect.calls)
	}
}

func TestConnectServerCreateDeletesServerWhenItemFails(t *testing.T) {
	connect := &fakeConnect{}
	r := &OnePasswordConnectServerResource{connect: connect, items: &fakeItems{createErr: errors.New("no access to vault")}}

	plan := resourceValue(t, r, serverModel(t, "ailab"))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error")
	}
	if last := connect.calls[len(connect.calls)-1]; last != "delete server SERVER1" {
		t.Errorf("the server without credentials was not deleted: %q", connect.calls)
	}
	if !resp.State.Raw.IsNull() {
		t.Error("state was saved for a deleted server")
	}
}

func readServer(t *testing.T, r *OnePasswordConnectServerResource, data OnePasswordConnectServerResourceModel) *fwresource.ReadResponse {
	t.Helper()
	state := resourceValue(t, r, data)
	resp := &fwresource.ReadResponse{State: state}
	r.Read(context.Background(), fwresource.ReadRequest{State: state}, resp)
	return resp
}

func createdServerModel(t *testing.T) OnePasswordConnectServerResourceModel {
	data := serverModel(t, "ailab", "V1")
	data.ID = types.StringValue("SERVER1")
	data.CredentialsItemID = types.StringValue("ITEM1")
	return data
}

func TestConnectServerReadRemovesDeletedServer(t *testing.T) {
	r := &OnePasswordConnectServerResource{connect: &fakeConnect{}, items: &fakeItems{}}
	resp := readServer(t, r, createdServerModel(t))
	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Errorf("deleted server kept in state: %v", resp.Diagnostics)
	}
}

func TestConnectServerReadWarnsWhenCredentialsItemIsGone(t *testing.T) {
	connect := &fakeConnect{servers: []cli.ConnectServer{{ID: "SERVER1", Name: "renamed"}}}
	r := &OnePasswordConnectServerResource{connect: connect, items: &fakeItems{}}
	resp := readServer(t, r, createdServerModel(t))

	if resp.Diagnostics.HasError() || len(resp.Diagnostics.Warnings()) != 1 {
		t.Fatalf("expected one warning, got %v", resp.Diagnostics)
	}
	var state OnePasswordConnectServerResourceModel
	resp.State.Get(context.Background(), &state)
	if state.Name.ValueString() != "renamed" {
		t.Errorf("name not refreshed: %q", state.Name.ValueString())
	}
}

func TestConnectServerUpdateRenamesAndChangesVaults(t *testing.T) {
	ctx := context.Background()
	connect := &fakeConnect{}
	r := &OnePasswordConnectServerResource{connect: connect, items: &fakeItems{}}

	before := createdServerModel(t)
	before.Vaults = stringSet(t, "KEEP", "DROP")
	after := createdServerModel(t)
	after.Name = types.StringValue("ailab-2")
	after.Vaults = stringSet(t, "KEEP", "ADD")

	state := resourceValue(t, r, before)
	plan := resourceValue(t, r, after)
	resp := &fwresource.UpdateResponse{State: state}
	r.Update(ctx, fwresource.UpdateRequest{State: state, Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}

	expected := []string{"rename server SERVER1 ailab-2", "grant SERVER1 ADD", "revoke SERVER1 DROP"}
	if !reflect.DeepEqual(connect.calls, expected) {
		t.Errorf("calls = %q", connect.calls)
	}
}

func TestConnectServerDeleteRemovesCredentialsItem(t *testing.T) {
	ctx := context.Background()
	connect := &fakeConnect{}
	items := &fakeItems{items: map[string]*model.Item{"ITEM1": {ID: "ITEM1"}}}
	r := &OnePasswordConnectServerResource{connect: connect, items: items}

	state := resourceValue(t, r, createdServerModel(t))
	resp := &fwresource.DeleteResponse{State: state}
	r.Delete(ctx, fwresource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if len(items.items) != 0 || !reflect.DeepEqual(connect.calls, []string{"delete server SERVER1"}) {
		t.Errorf("items left %v, calls %q", items.items, connect.calls)
	}

	// Deleting again, with both already gone, is not an error.
	r.Delete(ctx, fwresource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("second delete failed: %v", resp.Diagnostics)
	}
}

func tokenModel(t *testing.T, name string, vaults map[string]string) OnePasswordConnectTokenResourceModel {
	t.Helper()
	objectType := types.ObjectType{AttrTypes: map[string]attr.Type{"id": types.StringType, "access": types.StringType}}
	ids := make([]string, 0, len(vaults))
	for id := range vaults {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var models []OnePasswordConnectTokenVaultModel
	for _, id := range ids {
		access := types.StringNull()
		if vaults[id] != "" {
			access = types.StringValue(vaults[id])
		}
		models = append(models, OnePasswordConnectTokenVaultModel{ID: types.StringValue(id), Access: access})
	}
	set, diagnostics := types.SetValueFrom(context.Background(), objectType, models)
	if diagnostics.HasError() {
		t.Fatal(diagnostics)
	}
	return OnePasswordConnectTokenResourceModel{
		ID:          types.StringUnknown(),
		ServerID:    types.StringValue("SERVER1"),
		Name:        types.StringValue(name),
		Vaults:      set,
		ExpiresIn:   types.StringValue("90d"),
		TokenVault:  types.StringValue("INFRA"),
		TokenTitle:  types.StringValue("connect-ailab-token"),
		TokenItemID: types.StringUnknown(),
	}
}

func TestConnectTokenCreateWritesTokenItem(t *testing.T) {
	ctx := context.Background()
	connect := &fakeConnect{tokenValue: "eyJ-secret"}
	items := &fakeItems{}
	r := &OnePasswordConnectTokenResource{connect: connect, items: items}

	plan := resourceValue(t, r, tokenModel(t, "operator", map[string]string{"V1": "", "V2": "read"}))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(ctx, fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}

	if !reflect.DeepEqual(connect.calls, []string{"create token SERVER1 operator [{V1 } {V2 r}] 90d"}) {
		t.Errorf("calls = %q", connect.calls)
	}
	if got := items.field(t, "ITEM1", "token"); got != "eyJ-secret" {
		t.Errorf("token field = %q", got)
	}
	var state OnePasswordConnectTokenResourceModel
	resp.State.Get(ctx, &state)
	if state.ID.ValueString() != "TOKEN1" || state.TokenItemID.ValueString() != "ITEM1" {
		t.Errorf("state = %+v", state)
	}
}

func TestConnectTokenCreateRefusesActiveName(t *testing.T) {
	connect := &fakeConnect{tokens: []cli.ConnectToken{
		{ID: "OLD", Name: "revoked-one", State: "REVOKED"},
		{ID: "ACTIVE", Name: "operator", State: "ACTIVE"},
	}}
	r := &OnePasswordConnectTokenResource{connect: connect, items: &fakeItems{}}

	plan := resourceValue(t, r, tokenModel(t, "operator", map[string]string{"V1": ""}))
	resp := &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if !resp.Diagnostics.HasError() || len(connect.calls) != 0 {
		t.Errorf("expected a refusal without issuing a token: %v %q", resp.Diagnostics, connect.calls)
	}

	// A revoked token's name can be used again.
	plan = resourceValue(t, r, tokenModel(t, "revoked-one", map[string]string{"V1": ""}))
	resp = &fwresource.CreateResponse{State: emptyState(plan)}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: tfsdk.Plan(plan)}, resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("revoked name refused: %v", resp.Diagnostics)
	}
}

func createdTokenModel(t *testing.T) OnePasswordConnectTokenResourceModel {
	data := tokenModel(t, "operator", map[string]string{"V1": ""})
	data.ID = types.StringValue("TOKEN1")
	data.TokenItemID = types.StringValue("ITEM1")
	return data
}

func TestConnectTokenReadRemovesRevokedToken(t *testing.T) {
	for name, connect := range map[string]*fakeConnect{
		"revoked":     {tokens: []cli.ConnectToken{{ID: "TOKEN1", Name: "operator", State: "REVOKED"}}},
		"server gone": {getErr: fmt.Errorf("op connect token list: %w", cli.ErrNotFound)},
	} {
		t.Run(name, func(t *testing.T) {
			r := &OnePasswordConnectTokenResource{connect: connect, items: &fakeItems{items: map[string]*model.Item{"ITEM1": {}}}}
			state := resourceValue(t, r, createdTokenModel(t))
			resp := &fwresource.ReadResponse{State: state}
			r.Read(context.Background(), fwresource.ReadRequest{State: state}, resp)
			if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
				t.Errorf("token kept in state: %v", resp.Diagnostics)
			}
		})
	}
}

func TestConnectTokenReadWarnsWhenItemIsGone(t *testing.T) {
	connect := &fakeConnect{tokens: []cli.ConnectToken{{ID: "TOKEN1", Name: "operator", State: "ACTIVE"}}}
	r := &OnePasswordConnectTokenResource{connect: connect, items: &fakeItems{}}
	state := resourceValue(t, r, createdTokenModel(t))
	resp := &fwresource.ReadResponse{State: state}
	r.Read(context.Background(), fwresource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || len(resp.Diagnostics.Warnings()) != 1 || resp.State.Raw.IsNull() {
		t.Errorf("expected the token kept with one warning: %v", resp.Diagnostics)
	}
}

func TestConnectTokenUpdateOnlyRenames(t *testing.T) {
	connect := &fakeConnect{}
	r := &OnePasswordConnectTokenResource{connect: connect, items: &fakeItems{}}
	before := createdTokenModel(t)
	after := createdTokenModel(t)
	after.Name = types.StringValue("operator-2")

	state := resourceValue(t, r, before)
	resp := &fwresource.UpdateResponse{State: state}
	r.Update(context.Background(), fwresource.UpdateRequest{State: state, Plan: tfsdk.Plan(resourceValue(t, r, after))}, resp)
	if resp.Diagnostics.HasError() || !reflect.DeepEqual(connect.calls, []string{"rename token SERVER1 TOKEN1 operator-2"}) {
		t.Errorf("calls %q, diagnostics %v", connect.calls, resp.Diagnostics)
	}
}

func TestAccConnectResourcesRejectConnect(t *testing.T) {
	configs := map[string]string{
		"onepassword_connect_server": `
resource "onepassword_connect_server" "test" {
  name              = "ailab"
  credentials_vault = "INFRA"
  credentials_title = "connect-ailab"
}`,
		"onepassword_connect_token": `
resource "onepassword_connect_token" "test" {
  server_id   = "SERVER1"
  name        = "operator"
  vaults      = [{ id = "V1" }]
  token_vault = "INFRA"
  token_title = "connect-ailab-token"
}`,
	}
	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      testAccProviderConfig("http://127.0.0.1:1") + config,
					ExpectError: regexp.MustCompile(`cannot be used with 1Password Connect\s+authentication`),
				}},
			})
		})
	}
}
