package integration

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	tfconfig "github.com/1Password/terraform-provider-onepassword/v3/test/e2e/terraform/config"
	"github.com/1Password/terraform-provider-onepassword/v3/test/e2e/utils/cleanup"
	uuidutil "github.com/1Password/terraform-provider-onepassword/v3/test/e2e/utils/uuid"
)

func TestAccVaultResource(t *testing.T) {
	if os.Getenv("OP_TEST_VAULT_MANAGEMENT") == "" {
		t.Skip("set OP_TEST_VAULT_MANAGEMENT to run destructive vault-management tests")
	}
	if os.Getenv("OP_CONNECT_HOST") != "" || os.Getenv("OP_CONNECT_TOKEN") != "" {
		t.Skip("vault management is not supported with 1Password Connect")
	}

	groupID := os.Getenv("OP_TEST_VAULT_GROUP_ID")
	name := "Terraform acceptance vault " + uuid.NewString()
	description := "Created by terraform-provider-onepassword acceptance tests"
	updatedDescription := "Updated by terraform-provider-onepassword acceptance tests"
	var vaultUUID string

	createConfig := tfconfig.CreateConfigBuilder()(
		tfconfig.ProviderConfig(),
		tfconfig.VaultResourceConfig(name, description, false, groupID, []string{"read_items"}),
	)
	updateConfig := tfconfig.CreateConfigBuilder()(
		tfconfig.ProviderConfig(),
		tfconfig.VaultResourceConfig(name, updatedDescription, false, groupID, []string{"read_items", "create_items"}),
	)
	if os.Getenv("OP_ACCOUNT") == "" {
		// Service accounts cannot update vault metadata, but can manage permissions
		// for vaults they created.
		updateConfig = tfconfig.CreateConfigBuilder()(
			tfconfig.ProviderConfig(),
			tfconfig.VaultResourceConfig(name, description, false, groupID, []string{"read_items", "create_items"}),
		)
	}

	steps := []resource.TestStep{{
		Config: createConfig,
		Check: resource.ComposeAggregateTestCheckFunc(
			uuidutil.CaptureItemUUID(t, "onepassword_vault.test_vault", &vaultUUID),
			cleanup.RegisterVault(t, &vaultUUID),
			resource.TestCheckResourceAttr("onepassword_vault.test_vault", "name", name),
			resource.TestCheckResourceAttr("onepassword_vault.test_vault", "description", description),
			resource.TestCheckResourceAttr("onepassword_vault.test_vault", "allow_admins_access", "false"),
		),
	}}

	if groupID != "" {
		steps = append(steps, resource.TestStep{
			Config: updateConfig,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("onepassword_vault.test_vault", "group_permissions.#", "1"),
				resource.TestCheckResourceAttr("onepassword_vault.test_vault", "description", func() string {
					if os.Getenv("OP_ACCOUNT") != "" {
						return updatedDescription
					}
					return description
				}()),
			),
		})
		descriptionAfterUpdate := description
		if os.Getenv("OP_ACCOUNT") != "" {
			descriptionAfterUpdate = updatedDescription
		}
		steps = append(steps, resource.TestStep{
			Config: tfconfig.CreateConfigBuilder()(
				tfconfig.ProviderConfig(),
				tfconfig.VaultResourceConfig(name, descriptionAfterUpdate, false, "", nil),
			),
			Check: resource.TestCheckResourceAttr("onepassword_vault.test_vault", "group_permissions.#", "0"),
		})
	} else if os.Getenv("OP_ACCOUNT") != "" {
		steps = append(steps, resource.TestStep{
			Config: updateConfig,
			Check:  resource.TestCheckResourceAttr("onepassword_vault.test_vault", "description", updatedDescription),
		})
	}

	// Import into fresh state and apply the configuration that created the
	// vault: it must update in place, never replace the vault, and warn about
	// the group access it would overwrite.
	finalDescription := description
	if os.Getenv("OP_ACCOUNT") != "" {
		finalDescription = updatedDescription
	}
	var importedPermissions []string
	if groupID != "" {
		importedPermissions = []string{"read_items"}
	}
	importedConfig := tfconfig.CreateConfigBuilder()(
		tfconfig.ProviderConfig(),
		tfconfig.VaultResourceConfig(name, finalDescription, false, groupID, importedPermissions),
	)
	steps = append(steps,
		// Forget the vault without deleting it, as if it had been created outside.
		resource.TestStep{
			Config: tfconfig.CreateConfigBuilder()(tfconfig.ProviderConfig()) + `
removed {
  from = onepassword_vault.test_vault
}
`,
		},
		resource.TestStep{
			Config:             importedConfig,
			ResourceName:       "onepassword_vault.test_vault",
			ImportState:        true,
			ImportStatePersist: true,
			ImportStateIdFunc:  vaultImportID(&vaultUUID),
		},
		resource.TestStep{
			Config: importedConfig,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("onepassword_vault.test_vault", plancheck.ResourceActionUpdate),
				},
			},
		},
		// A second vault with the same name is refused instead of created.
		resource.TestStep{
			Config:      importedConfig + tfconfig.VaultResourceConfigNamed("duplicate", name)(),
			ExpectError: regexp.MustCompile(`already exists`),
		},
	)

	steps = append(steps,
		resource.TestStep{
			ResourceName:            "onepassword_vault.test_vault",
			ImportState:             true,
			ImportStateIdFunc:       vaultImportID(&vaultUUID),
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"allow_admins_access", "group_permissions"},
		},
		resource.TestStep{
			Config: tfconfig.CreateConfigBuilder()(tfconfig.ProviderConfig()),
		},
	)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

func vaultImportID(vaultUUID *string) resource.ImportStateIdFunc {
	return func(_ *terraform.State) (string, error) {
		if *vaultUUID == "" {
			return "", fmt.Errorf("vault UUID was not captured")
		}
		return "vaults/" + *vaultUUID, nil
	}
}
