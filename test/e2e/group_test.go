package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	tfconfig "github.com/1Password/terraform-provider-onepassword/v3/test/e2e/terraform/config"
)

// TestAccGroupDataSource looks a group up by UUID, then by the name that
// returned, and expects the same group back.
func TestAccGroupDataSource(t *testing.T) {
	groupID := os.Getenv("OP_TEST_GROUP_ID")
	if groupID == "" {
		t.Skip("set OP_TEST_GROUP_ID to the UUID of a group with access to a vault")
	}
	if os.Getenv("OP_CONNECT_HOST") != "" || os.Getenv("OP_CONNECT_TOKEN") != "" {
		t.Skip("groups are not supported with 1Password Connect")
	}

	config := tfconfig.CreateConfigBuilder()(tfconfig.ProviderConfig()) + fmt.Sprintf(`
data "onepassword_group" "by_uuid" {
  uuid = %q
}

data "onepassword_group" "by_name" {
  name = data.onepassword_group.by_uuid.name
}
`, groupID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.onepassword_group.by_uuid", "id", "groups/"+groupID),
				resource.TestCheckResourceAttr("data.onepassword_group.by_uuid", "state", "active"),
				resource.TestCheckResourceAttrPair("data.onepassword_group.by_name", "uuid", "data.onepassword_group.by_uuid", "uuid"),
				resource.TestCheckResourceAttrPair("data.onepassword_group.by_name", "type", "data.onepassword_group.by_uuid", "type"),
			),
		}},
	})
}
