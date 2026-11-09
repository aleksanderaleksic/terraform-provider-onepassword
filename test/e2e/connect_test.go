package integration

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	tfconfig "github.com/1Password/terraform-provider-onepassword/v3/test/e2e/terraform/config"
)

// TestAccConnectServerAndToken creates a vault, a Connect server with access
// to it and a token for the server, renames both, and destroys everything.
// The credentials and token items are written to the same vault.
func TestAccConnectServerAndToken(t *testing.T) {
	if os.Getenv("OP_TEST_CONNECT") == "" {
		t.Skip("set OP_TEST_CONNECT to run tests that create Connect servers")
	}
	if os.Getenv("OP_ACCOUNT") == "" {
		t.Skip("Connect servers can only be managed with desktop app authentication (OP_ACCOUNT)")
	}

	suffix := uuid.NewString()[:8]
	config := func(serverName, tokenName string) string {
		return tfconfig.CreateConfigBuilder()(tfconfig.ProviderConfig()) + fmt.Sprintf(`
resource "onepassword_vault" "test" {
  name = "Terraform acceptance connect %[1]s"
}

resource "onepassword_connect_server" "test" {
  name              = %[2]q
  vaults            = [onepassword_vault.test.uuid]
  credentials_vault = onepassword_vault.test.uuid
  credentials_title = "connect server credentials"
}

resource "onepassword_connect_token" "test" {
  server_id   = onepassword_connect_server.test.id
  name        = %[3]q
  vaults      = [{ id = onepassword_vault.test.uuid, access = "read" }]
  expires_in  = "1d"
  token_vault = onepassword_vault.test.uuid
  token_title = "connect token"
}
`, suffix, serverName, tokenName)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config("tf-acc-"+suffix, "operator"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("onepassword_connect_server.test", "id"),
					resource.TestCheckResourceAttrSet("onepassword_connect_server.test", "credentials_item_id"),
					resource.TestCheckResourceAttrSet("onepassword_connect_token.test", "id"),
					resource.TestCheckResourceAttrSet("onepassword_connect_token.test", "token_item_id"),
				),
			},
			{
				Config: config("tf-acc-renamed-"+suffix, "operator-renamed"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("onepassword_connect_server.test", "name", "tf-acc-renamed-"+suffix),
					resource.TestCheckResourceAttr("onepassword_connect_token.test", "name", "operator-renamed"),
				),
			},
		},
	})
}
