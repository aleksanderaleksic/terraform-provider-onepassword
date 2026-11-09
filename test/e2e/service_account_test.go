package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	tfconfig "github.com/1Password/terraform-provider-onepassword/v3/test/e2e/terraform/config"
)

// TestAccServiceAccount creates a service account with access to a new vault
// and destroys it. op can't delete service accounts, so every run leaves one
// behind; it expires after an hour and must be deleted in the web interface.
func TestAccServiceAccount(t *testing.T) {
	if os.Getenv("OP_TEST_SERVICE_ACCOUNT") == "" {
		t.Skip("set OP_TEST_SERVICE_ACCOUNT to run a test that leaves a service account behind")
	}
	if os.Getenv("OP_ACCOUNT") == "" {
		t.Skip("service accounts can only be created with desktop app authentication (OP_ACCOUNT)")
	}

	suffix := uuid.NewString()[:8]
	config := tfconfig.CreateConfigBuilder()(tfconfig.ProviderConfig()) + fmt.Sprintf(`
resource "onepassword_vault" "test" {
  name = "Terraform acceptance service account %[1]s"
}

resource "onepassword_service_account" "test" {
  name       = "tf-acc-%[1]s"
  expires_in = "1h"

  vaults = [{ id = onepassword_vault.test.uuid, permissions = ["read_items", "write_items"] }]

  token_vault = onepassword_vault.test.uuid
  token_title = "service account token"
}
`, suffix)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			Check:  resource.TestCheckResourceAttrSet("onepassword_service_account.test", "id"),
		}},
	})
}
